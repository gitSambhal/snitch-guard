// SnitchGuard - Host-Based Application Firewall Daemon
// Author: Suhail Akhtar (https://suhail.top)
// License: MIT
// Module: Traffic Interceptor & TLS SNI Parser

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionRequest represents an intercepted outbound network flow
type ConnectionRequest struct {
	ID          string       `json:"id"`
	Timestamp   time.Time    `json:"timestamp"`
	Process     *ProcessInfo `json:"process"`
	ProcessName string       `json:"process_name"`
	ProcessPath string       `json:"process_path"`
	PID         int          `json:"pid"`
	LocalAddr   string       `json:"local_addr"`
	RemoteIP    string       `json:"remote_ip"`
	RemotePort  int          `json:"remote_port"`
	Domain      string       `json:"domain"`
	Protocol    string       `json:"protocol"` // "tcp", "tls", "http", "udp"
	BytesSent   int64        `json:"bytes_sent"`
	BytesRecv   int64        `json:"bytes_recv"`
	State       string       `json:"state"` // "pending", "allowed", "blocked", "closed"
}

// Interceptor manages packet interception, SNI extraction, and forwarding
type Interceptor struct {
	mu          sync.RWMutex
	connections map[string]*ActiveFlow
	ruleEngine  *RuleEngine
	resolver    *ProcessResolver
	wsServer    *WSServer
	nextFlowID  uint64
	isRunning   bool
	listenAddr  string
}

// ActiveFlow tracks an ongoing live socket flow
type ActiveFlow struct {
	Req        *ConnectionRequest
	ClientConn net.Conn
	TargetConn net.Conn
	DecisionCh chan Action
	CreatedAt  time.Time
	LastActive time.Time
}

// NewInterceptor creates a new traffic interceptor
func NewInterceptor(listenAddr string, re *RuleEngine, pr *ProcessResolver, ws *WSServer) *Interceptor {
	return &Interceptor{
		connections: make(map[string]*ActiveFlow),
		ruleEngine:  re,
		resolver:    pr,
		wsServer:    ws,
		listenAddr:  listenAddr,
	}
}

// Start begins listening on the interceptor port (e.g. 127.0.0.1:9096 or transparent redirect)
//
// -----------------------------------------------------------------------------------------
// PRODUCTION KERNEL DRIVER INTEGRATION:
// -----------------------------------------------------------------------------------------
// 1. Linux (eBPF + iptables / nftables):
//    - Attach an eBPF `sock_ops` program to the root cgroup `/sys/fs/cgroup`.
//    - Or configure `iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner snitchguard -j REDIRECT --to-ports 9096`
//    - The daemon reads `SO_ORIGINAL_DST` via `getsockopt(SOL_IP, SO_ORIGINAL_DST)` to retrieve destination.
//
// 2. macOS (NetworkExtension Framework):
//    - Implement `NEFilterDataProvider` and override `handleNewFlow(_ flow: NEFilterSocketFlow)`.
//    - Query flow for `remoteEndpoint` and process path.
//    - Return `.pause` to block until the UI popup verdict is received, then return `.allow` or `.drop`.
//
// 3. Windows (Windows Filtering Platform - WFP):
//    - Register a kernel callout driver at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
//    - Call `FwpsPendOperation0` on unmatched connections to suspend TCP handshake.
//    - IPC message sent to user-mode daemon; on verdict call `FwpsCompleteOperation0(verdict)`.
func (ic *Interceptor) Start() error {
	listener, err := net.Listen("tcp", ic.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start interceptor listener: %w", err)
	}

	ic.isRunning = true
	log.Printf("[Interceptor] Outbound traffic proxy/interceptor listening on %s", ic.listenAddr)

	go func() {
		for ic.isRunning {
			conn, err := listener.Accept()
			if err != nil {
				if !ic.isRunning {
					break
				}
				log.Printf("[Interceptor] Accept error: %v", err)
				continue
			}

			go ic.handleInterceptedConn(conn)
		}
	}()

	return nil
}

// handleInterceptedConn inspects incoming packet headers, extracts SNI, resolves process, and evaluates rules
func (ic *Interceptor) handleInterceptedConn(clientConn net.Conn) {
	defer clientConn.Close()

	flowID := fmt.Sprintf("flow-%d", atomic.AddUint64(&ic.nextFlowID, 1))
	localAddr := clientConn.RemoteAddr().String() // Client side of socket
	remoteAddr := clientConn.LocalAddr().String()  // Interceptor destination or original dst

	// Peek initial bytes without discarding for SNI / HTTP extraction
	headerBuf := make([]byte, 2048)
	n, err := clientConn.Read(headerBuf)
	if err != nil && err != io.EOF {
		log.Printf("[Interceptor] Failed reading initial bytes: %v", err)
		return
	}
	payload := headerBuf[:n]

	// Extract SNI Domain or HTTP Host
	domain, protocol := ExtractDomainAndProtocol(payload)
	remoteIP, remotePort := parseHostPort(remoteAddr)

	// Resolve calling process (PID, Binary Path, Signature)
	procInfo := ic.resolver.Resolve(localAddr, remoteAddr, protocol)

	req := &ConnectionRequest{
		ID:          flowID,
		Timestamp:   time.Now(),
		Process:     procInfo,
		ProcessName: procInfo.Name,
		ProcessPath: procInfo.Path,
		PID:         procInfo.PID,
		LocalAddr:   localAddr,
		RemoteIP:    remoteIP,
		RemotePort:  remotePort,
		Domain:      domain,
		Protocol:    protocol,
		State:       "pending",
	}

	log.Printf("[Interceptor] New Connection: [%s] PID:%d (%s) -> %s (%s:%d)",
		protocol, req.PID, req.ProcessName, req.Domain, req.RemoteIP, req.RemotePort)

	// Evaluate Rules
	action, matchedRule, matched := ic.ruleEngine.Evaluate(req)

	if matched {
		if action == ActionAllow {
			log.Printf("[Interceptor] Auto-ALLOWED by rule %s", matchedRule.ID)
			req.State = "allowed"
			ic.wsServer.BroadcastTrafficEvent(req)
			ic.forwardTraffic(clientConn, req, payload)
		} else {
			log.Printf("[Interceptor] Auto-BLOCKED by rule %s", matchedRule.ID)
			req.State = "blocked"
			ic.wsServer.BroadcastTrafficEvent(req)
		}
		return
	}

	// No rule match -> Pause flow, register decision channel, and broadcast alert to Neutralino UI
	decisionCh := make(chan Action, 1)
	flow := &ActiveFlow{
		Req:        req,
		ClientConn: clientConn,
		DecisionCh: decisionCh,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
	}

	ic.mu.Lock()
	ic.connections[flowID] = flow
	ic.mu.Unlock()

	defer func() {
		ic.mu.Lock()
		delete(ic.connections, flowID)
		ic.mu.Unlock()
	}()

	// Push Pop-Up Alert via WebSocket to Neutralino Client
	ic.wsServer.PushAlert(req)

	// Wait for user decision or 30-second timeout
	select {
	case verdict := <-decisionCh:
		if verdict == ActionAllow {
			log.Printf("[Interceptor] User ALLOWED flow %s", flowID)
			req.State = "allowed"
			ic.wsServer.BroadcastTrafficEvent(req)
			ic.forwardTraffic(clientConn, req, payload)
		} else {
			log.Printf("[Interceptor] User BLOCKED flow %s", flowID)
			req.State = "blocked"
			ic.wsServer.BroadcastTrafficEvent(req)
		}
	case <-time.After(30 * time.Second):
		log.Printf("[Interceptor] Flow %s timed out waiting for decision. Defaulting to BLOCK.", flowID)
		req.State = "blocked"
		ic.wsServer.BroadcastTrafficEvent(req)
	}
}

// DeliverVerdict passes user's decision from the Neutralino UI to the waiting connection flow
func (ic *Interceptor) DeliverVerdict(flowID string, verdict Action) bool {
	ic.mu.RLock()
	flow, exists := ic.connections[flowID]
	ic.mu.RUnlock()

	if !exists {
		return false
	}

	select {
	case flow.DecisionCh <- verdict:
		return true
	default:
		return false
	}
}

// forwardTraffic proxies data between client and upstream target
func (ic *Interceptor) forwardTraffic(clientConn net.Conn, req *ConnectionRequest, initialPayload []byte) {
	targetAddr := net.JoinHostPort(req.RemoteIP, fmt.Sprintf("%d", req.RemotePort))
	if req.Domain != "" && req.Domain != "unknown" && !strings.Contains(req.Domain, ":") {
		targetAddr = net.JoinHostPort(req.Domain, fmt.Sprintf("%d", req.RemotePort))
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("[Interceptor] Dial upstream %s failed: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Write initial peeked payload to upstream
	if len(initialPayload) > 0 {
		if _, err := targetConn.Write(initialPayload); err != nil {
			log.Printf("[Interceptor] Failed writing initial payload: %v", err)
			return
		}
		atomic.AddInt64(&req.BytesSent, int64(len(initialPayload)))
	}

	// Bi-directional pipe
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, er := clientConn.Read(buf)
			if nr > 0 {
				nw, ew := targetConn.Write(buf[:nr])
				if nw > 0 {
					atomic.AddInt64(&req.BytesSent, int64(nw))
				}
				if ew != nil {
					break
				}
			}
			if er != nil {
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, er := targetConn.Read(buf)
			if nr > 0 {
				nw, ew := clientConn.Write(buf[:nr])
				if nw > 0 {
					atomic.AddInt64(&req.BytesRecv, int64(nw))
				}
				if ew != nil {
					break
				}
			}
			if er != nil {
				break
			}
		}
	}()

	wg.Wait()
	req.State = "closed"
	ic.wsServer.BroadcastTrafficEvent(req)
}

// -----------------------------------------------------------------------------------------
// TLS SNI & HTTP HOST EXTRACTION:
// -----------------------------------------------------------------------------------------

// ExtractDomainAndProtocol inspects the raw payload for TLS ClientHello or HTTP headers
func ExtractDomainAndProtocol(data []byte) (string, string) {
	if len(data) == 0 {
		return "unknown", "tcp"
	}

	// Check for TLS ClientHello Handshake (0x16 = Record Type Handshake, 0x03 0x01/0x02/0x03 = TLS version)
	if data[0] == 0x16 && len(data) > 5 && data[1] == 0x03 {
		sni, ok := extractSNI(data)
		if ok && sni != "" {
			return sni, "tls"
		}
		return "unknown.tls.host", "tls"
	}

	// Check for HTTP Methods (GET, POST, HEAD, PUT, DELETE, CONNECT, OPTIONS)
	httpMethods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS "}
	for _, m := range httpMethods {
		if strings.HasPrefix(string(data), m) {
			host := extractHTTPHost(data)
			if host != "" {
				return host, "http"
			}
			return "unknown.http", "http"
		}
	}

	return "raw-socket", "tcp"
}

// extractSNI parses the TLS ClientHello byte stream to extract server_name extension (RFC 6066)
func extractSNI(data []byte) (string, bool) {
	if len(data) < 43 {
		return "", false
	}

	// Handshake Message Type must be 1 (ClientHello)
	if data[5] != 0x01 {
		return "", false
	}

	// Skip TLS Record Header (5 bytes) + Handshake Type & Length (4 bytes) + Client Version (2) + Random (32) = 43
	offset := 43
	if len(data) <= offset {
		return "", false
	}

	// Skip Session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen
	if len(data) <= offset+2 {
		return "", false
	}

	// Skip Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if len(data) <= offset+1 {
		return "", false
	}

	// Skip Compression Methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen
	if len(data) <= offset+2 {
		return "", false
	}

	// Extensions Length
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	end := offset + extensionsLen
	if len(data) < end {
		end = len(data)
	}

	// Iterate Extensions to find type 0x0000 (server_name)
	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if extType == 0 { // server_name extension
			if offset+extLen > end {
				return "", false
			}
			// ServerNameList length (2 bytes) + ServerName Type (1 byte: 0 = host_name) + HostName length (2 bytes)
			if extLen < 5 {
				return "", false
			}
			nameType := data[offset+2]
			if nameType == 0 { // host_name
				nameLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
				if offset+5+nameLen <= end {
					sni := string(data[offset+5 : offset+5+nameLen])
					return sni, true
				}
			}
		}

		offset += extLen
	}

	return "", false
}

// extractHTTPHost parses standard "Host: example.com" header from HTTP payload
func extractHTTPHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				host := string(bytes.TrimSpace(parts[1]))
				// Remove port if present e.g. "localhost:8080"
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				return host
			}
		}
	}
	return ""
}

func parseHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
