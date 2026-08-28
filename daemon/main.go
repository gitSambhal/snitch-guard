// SnitchGuard - Host-Based Application Firewall Daemon
// Author: Suhail Akhtar (https://suhail.top)
// License: MIT
// Module: Main Daemon Server & WebSocket IPC Hub

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow Neutralinojs desktop client origin
		return true
	},
}

// IPCMessage represents bidirectional JSON messages across the internal WebSocket
type IPCMessage struct {
	Type    string          `json:"type"`              // e.g. "ALERT_PROMPT", "DECISION", "GET_RULES", "RULE_LIST"
	Payload json.RawMessage `json:"payload,omitempty"` // Polymorphic payload
}

// DecisionPayload represents user choice from Neutralino alert window
type DecisionPayload struct {
	FlowID        string   `json:"flow_id"`
	Action        Action   `json:"action"`          // "allow" or "block"
	Duration      Duration `json:"duration"`        // "once", "session", "always"
	ApplyWildcard bool     `json:"apply_wildcard"`  // whether to create *.domain rule
	Domain        string   `json:"domain"`
	ProcessPath   string   `json:"process_path"`
	ProcessName   string   `json:"process_name"`
	RemotePort    int      `json:"remote_port"`
	Protocol      string   `json:"protocol"`
}

// DaemonStats reports live health & throughput metrics
type DaemonStats struct {
	ActiveFlows     int       `json:"active_flows"`
	TotalRules      int       `json:"total_rules"`
	BlockedCount    int64     `json:"blocked_count"`
	AllowedCount    int64     `json:"allowed_count"`
	PromptCount     int64     `json:"prompt_count"`
	BytesTotal      int64     `json:"bytes_total"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	DaemonVersion   string    `json:"daemon_version"`
	PlatformDriver  string    `json:"platform_driver"`
	StartTime       time.Time `json:"start_time"`
}

// WSServer coordinates WebSocket connections from Neutralino UI
type WSServer struct {
	mu          sync.RWMutex
	clients     map[*websocket.Conn]bool
	interceptor *Interceptor
	ruleEngine  *RuleEngine
	stats       DaemonStats
	statsMu     sync.RWMutex
}

// NewWSServer creates a new IPC WebSocket server
func NewWSServer(re *RuleEngine) *WSServer {
	return &WSServer{
		clients:    make(map[*websocket.Conn]bool),
		ruleEngine: re,
		stats: DaemonStats{
			DaemonVersion:  "v1.0.0",
			PlatformDriver: "eBPF/NetworkExtension/WFP Hybrid Mock",
			StartTime:      time.Now(),
		},
	}
}

// SetInterceptor attaches the interceptor reference
func (ws *WSServer) SetInterceptor(ic *Interceptor) {
	ws.interceptor = ic
}

func (ws *WSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WSServer] Upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ws.mu.Lock()
	ws.clients[conn] = true
	ws.mu.Unlock()
	log.Printf("[WSServer] Neutralino desktop client connected: %s", conn.RemoteAddr())

	// Push initial rule list and system state on connect
	ws.sendRules(conn)
	ws.sendStats(conn)

	defer func() {
		ws.mu.Lock()
		delete(ws.clients, conn)
		ws.mu.Unlock()
		log.Printf("[WSServer] Client disconnected: %s", conn.RemoteAddr())
	}()

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg IPCMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			log.Printf("[WSServer] Invalid JSON: %v", err)
			continue
		}

		ws.handleClientMessage(conn, &msg)
	}
}

// handleClientMessage dispatches client actions
func (ws *WSServer) handleClientMessage(conn *websocket.Conn, msg *IPCMessage) {
	switch msg.Type {
	case "DECISION":
		var dec DecisionPayload
		if err := json.Unmarshal(msg.Payload, &dec); err != nil {
			log.Printf("[WSServer] Failed parsing decision: %v", err)
			return
		}
		ws.handleDecision(&dec)

	case "GET_RULES":
		ws.sendRules(conn)

	case "ADD_RULE":
		var rule FirewallRule
		if err := json.Unmarshal(msg.Payload, &rule); err == nil {
			_ = ws.ruleEngine.AddRule(&rule)
			ws.broadcastRules()
		}

	case "DELETE_RULE":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &req); err == nil {
			ws.ruleEngine.DeleteRule(req.ID)
			ws.broadcastRules()
		}

	case "SIMULATE_TRAFFIC":
		var simReq struct {
			ProcessName string `json:"process_name"`
			Domain      string `json:"domain"`
			RemoteIP    string `json:"remote_ip"`
			Port        int    `json:"port"`
			Protocol    string `json:"protocol"`
		}
		if err := json.Unmarshal(msg.Payload, &simReq); err == nil {
			go ws.simulateIncomingTraffic(simReq.ProcessName, simReq.Domain, simReq.RemoteIP, simReq.Port, simReq.Protocol)
		}
	}
}

// handleDecision persists rules and resumes the waiting network connection
func (ws *WSServer) handleDecision(dec *DecisionPayload) {
	log.Printf("[WSServer] Received decision for flow %s: %s (Duration: %s, Wildcard: %v)",
		dec.FlowID, dec.Action, dec.Duration, dec.ApplyWildcard)

	// Update stats
	ws.statsMu.Lock()
	if dec.Action == ActionAllow {
		ws.stats.AllowedCount++
	} else {
		ws.stats.BlockedCount++
	}
	ws.statsMu.Unlock()

	// If Duration is Session or Always, create and store rule
	if dec.Duration == DurationSession || dec.Duration == DurationAlways || dec.Duration == DurationOnce {
		domainPattern := dec.Domain
		if dec.ApplyWildcard && domainPattern != "" && domainPattern != "*" {
			parts := filepath.Ext(domainPattern)
			if parts != "" {
				domainPattern = "*." + domainPattern
			}
		}

		newRule := &FirewallRule{
			ID:            fmt.Sprintf("rule-%d", time.Now().UnixNano()),
			ProcessPath:   dec.ProcessPath,
			ProcessName:   dec.ProcessName,
			DomainPattern: domainPattern,
			RemoteIP:      "*",
			RemotePort:    dec.RemotePort,
			Protocol:      dec.Protocol,
			Action:        dec.Action,
			Duration:      dec.Duration,
			CreatedAt:     time.Now(),
			Comment:       fmt.Sprintf("Created via prompt decision for %s", dec.Domain),
		}

		_ = ws.ruleEngine.AddRule(newRule)
		ws.broadcastRules()
	}

	// Release paused socket flow in interceptor
	if ws.interceptor != nil {
		ws.interceptor.DeliverVerdict(dec.FlowID, dec.Action)
	}
}

// PushAlert sends an interactive connection alert modal trigger to the Neutralino UI
func (ws *WSServer) PushAlert(req *ConnectionRequest) {
	ws.statsMu.Lock()
	ws.stats.PromptCount++
	ws.statsMu.Unlock()

	payloadBytes, _ := json.Marshal(req)
	msg := IPCMessage{
		Type:    "ALERT_PROMPT",
		Payload: payloadBytes,
	}

	ws.broadcast(&msg)
}

// BroadcastTrafficEvent notifies the UI of live connection status changes & bandwidth
func (ws *WSServer) BroadcastTrafficEvent(req *ConnectionRequest) {
	payloadBytes, _ := json.Marshal(req)
	msg := IPCMessage{
		Type:    "TRAFFIC_EVENT",
		Payload: payloadBytes,
	}
	ws.broadcast(&msg)
}

func (ws *WSServer) sendRules(conn *websocket.Conn) {
	rules := ws.ruleEngine.GetAllRules()
	payloadBytes, _ := json.Marshal(rules)
	msg := IPCMessage{
		Type:    "RULE_LIST",
		Payload: payloadBytes,
	}
	bytes, _ := json.Marshal(msg)
	_ = conn.WriteMessage(websocket.TextMessage, bytes)
}

func (ws *WSServer) broadcastRules() {
	rules := ws.ruleEngine.GetAllRules()
	payloadBytes, _ := json.Marshal(rules)
	msg := IPCMessage{
		Type:    "RULE_LIST",
		Payload: payloadBytes,
	}
	ws.broadcast(&msg)
}

func (ws *WSServer) sendStats(conn *websocket.Conn) {
	ws.statsMu.RLock()
	st := ws.stats
	st.TotalRules = len(ws.ruleEngine.GetAllRules())
	st.UptimeSeconds = int64(time.Since(st.StartTime).Seconds())
	ws.statsMu.RUnlock()

	payloadBytes, _ := json.Marshal(st)
	msg := IPCMessage{
		Type:    "STATS_UPDATE",
		Payload: payloadBytes,
	}
	bytes, _ := json.Marshal(msg)
	_ = conn.WriteMessage(websocket.TextMessage, bytes)
}

func (ws *WSServer) broadcast(msg *IPCMessage) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	bytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for conn := range ws.clients {
		_ = conn.WriteMessage(websocket.TextMessage, bytes)
	}
}

// simulateIncomingTraffic generates simulated connection requests to test firewall prompts
func (ws *WSServer) simulateIncomingTraffic(procName, domain, ip string, port int, protocol string) {
	if procName == "" {
		procName = "curl"
	}
	if domain == "" {
		domain = "telemetry.dropbox.com"
	}
	if ip == "" {
		ip = "162.125.6.20"
	}
	if port == 0 {
		port = 443
	}
	if protocol == "" {
		protocol = "tls"
	}

	req := &ConnectionRequest{
		ID: fmt.Sprintf("sim-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Process: &ProcessInfo{
			PID:         50234,
			Name:        procName,
			Path:        "/usr/bin/" + procName,
			CommandLine: fmt.Sprintf("%s https://%s", procName, domain),
			User:        "suhail",
			Signature:   "Valid App Store / Notarized",
		},
		ProcessName: procName,
		ProcessPath: "/usr/bin/" + procName,
		PID:         50234,
		LocalAddr:   "192.168.1.100:54321",
		RemoteIP:    ip,
		RemotePort:  port,
		Domain:      domain,
		Protocol:    protocol,
		State:       "pending",
	}

	action, _, matched := ws.ruleEngine.Evaluate(req)
	if matched {
		if action == ActionAllow {
			req.State = "allowed"
		} else {
			req.State = "blocked"
		}
		ws.BroadcastTrafficEvent(req)
		return
	}

	// Trigger interactive alert in Neutralino UI
	ws.PushAlert(req)
}

func main() {
	wsPort := flag.Int("ws-port", 9095, "Internal WebSocket IPC port for Neutralino client")
	proxyPort := flag.Int("proxy-port", 9096, "Intercepted traffic listener port")
	rulesFile := flag.String("rules", "firewall_rules.json", "Path to JSON firewall rules database")
	flag.Parse()

	log.Println("==================================================================")
	log.Println(" SnitchGuard Daemon - Elevated Host Application Firewall")
	log.Println(" Author: Suhail Akhtar (https://suhail.top)")
	log.Printf(" Running with PID: %d (UID: %d)", os.Getpid(), os.Getuid())
	log.Println("==================================================================")

	// 1. Initialize Rule Engine
	ruleEngine := NewRuleEngine(*rulesFile)

	// 2. Initialize Process Resolver
	processResolver := NewProcessResolver()

	// 3. Initialize WebSocket IPC Hub
	wsServer := NewWSServer(ruleEngine)

	// 4. Initialize Interceptor
	interceptor := NewInterceptor(fmt.Sprintf("127.0.0.1:%d", *proxyPort), ruleEngine, processResolver, wsServer)
	wsServer.SetInterceptor(interceptor)

	if err := interceptor.Start(); err != nil {
		log.Printf("[Warning] Could not bind proxy on :%d (Mock mode will handle flows): %v", *proxyPort, err)
	}

	// 5. Start WebSocket Server for Neutralino UI
	http.Handle("/ws", wsServer)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": "v1.0.0"})
	})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", *wsPort)
	server := &http.Server{
		Addr: serverAddr,
	}

	go func() {
		log.Printf("[IPC] WebSocket server listening on ws://%s/ws", serverAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[IPC] Server error: %v", err)
		}
	}()

	// Ticker for periodic stats broadcast
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			wsServer.mu.RLock()
			for conn := range wsServer.clients {
				wsServer.sendStats(conn)
			}
			wsServer.mu.RUnlock()
		}
	}()

	// Graceful Shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("\n[Daemon] Received shutdown signal. Cleaning up rules and closing sockets...")
	_ = server.Close()
	log.Println("[Daemon] SnitchGuard Daemon stopped gracefully.")
}
