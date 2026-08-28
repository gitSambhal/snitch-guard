// SnitchGuard - Host-Based Application Firewall Daemon
// Author: Suhail Akhtar (https://suhail.top)
// License: MIT
// Module: Socket-to-PID and Process Binary Resolver

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// ProcessInfo contains metadata about the local binary initiating a connection
type ProcessInfo struct {
	PID         int      `json:"pid"`
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	CommandLine string   `json:"command_line,omitempty"`
	User        string   `json:"user,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	Signature   string   `json:"signature,omitempty"`
	Arguments   []string `json:"arguments,omitempty"`
}

// ProcessResolver resolves remote/local TCP socket pairs to the originating process
type ProcessResolver struct {
	mu    sync.RWMutex
	cache map[string]*ProcessInfo // key: "localIP:localPort-remoteIP:remotePort"
}

// NewProcessResolver instantiates a new resolver
func NewProcessResolver() *ProcessResolver {
	return &ProcessResolver{
		cache: make(map[string]*ProcessInfo),
	}
}

// Resolve identifies the local process responsible for the given network connection.
// In a full production implementation, this interfaces with OS kernel APIs.
func (pr *ProcessResolver) Resolve(localAddr, remoteAddr, protocol string) *ProcessInfo {
	pr.mu.RLock()
	key := fmt.Sprintf("%s-%s", localAddr, remoteAddr)
	if info, found := pr.cache[key]; found {
		pr.mu.RUnlock()
		return info
	}
	pr.mu.RUnlock()

	// Platform-Specific Resolution Strategy
	info := pr.resolveByPlatform(localAddr, remoteAddr, protocol)

	pr.mu.Lock()
	pr.cache[key] = info
	pr.mu.Unlock()

	return info
}

// resolveByPlatform executes native system introspection based on runtime OS
func (pr *ProcessResolver) resolveByPlatform(localAddr, remoteAddr, protocol string) *ProcessInfo {
	switch runtime.GOOS {
	case "linux":
		return pr.resolveLinux(localAddr, remoteAddr)
	case "darwin":
		return pr.resolveDarwin(localAddr, remoteAddr)
	case "windows":
		return pr.resolveWindows(localAddr, remoteAddr)
	default:
		return pr.resolveGenericFallback(remoteAddr)
	}
}

// -----------------------------------------------------------------------------------------
// PRODUCTION INTEGRATION NOTES:
// -----------------------------------------------------------------------------------------

// resolveLinux:
// In production:
// 1. Inspect `/proc/net/tcp` and `/proc/net/tcp6` to find the socket inode.
// 2. Scan `/proc/[pid]/fd/*` using readlink to match `socket:[inode]`.
// 3. Read `/proc/[pid]/exe` to obtain the full binary path and `/proc/[pid]/cmdline` for args.
// 4. In modern kernels (Linux 5.4+), an eBPF `sock_ops` or `cgroup_skb` hook provides direct
//    `bpf_get_current_pid_tgid()` during the `connect()` syscall before the packet hits the wire.
func (pr *ProcessResolver) resolveLinux(localAddr, remoteAddr string) *ProcessInfo {
	// Simulated Linux Process Mapping for testing & prototype
	pid := os.Getpid()
	exePath, _ := os.Executable()
	baseName := filepath.Base(exePath)

	return &ProcessInfo{
		PID:         pid,
		Name:        baseName,
		Path:        exePath,
		CommandLine: strings.Join(os.Args, " "),
		User:        "root",
		Signature:   "System Verified (ELF)",
	}
}

// resolveDarwin:
// In production:
// 1. Call `proc_pidinfo(PID, PROC_PIDLISTFDS)` from `<libproc.h>`.
// 2. Iterate descriptors with `PROC_PIDFDSOCKETINFO` to match `so_tuple` (laddr, raddr, lport, rport).
// 3. Call `proc_pidpath(pid, buffer, sizeof(buffer))` to get the Mach-O binary path.
// 4. Verify code signature via `SecCodeCopySelf` / `SecCodeCheckValidity`.
// 5. In macOS NetworkExtension (SystemExtension), `NEFilterSocketFlow` provides `remoteEndpoint`
//    and audit token automatically in kernel space.
func (pr *ProcessResolver) resolveDarwin(localAddr, remoteAddr string) *ProcessInfo {
	return &ProcessInfo{
		PID:         os.Getpid(),
		Name:        "snitchguard-daemon",
		Path:        "/usr/local/bin/snitchguard-daemon",
		CommandLine: "/usr/local/bin/snitchguard-daemon --intercept",
		User:        "root",
		Signature:   "Apple Code Signed / Verified",
	}
}

// resolveWindows:
// In production:
// 1. Call `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_ALL` from `iphlpapi.dll`.
// 2. Match local/remote IP and ports in `MIB_TCPROW_OWNER_PID` to find `dwOwningPid`.
// 3. Open process with `PROCESS_QUERY_LIMITED_INFORMATION` and call `QueryFullProcessImageNameW`.
// 4. In Windows Filtering Platform (WFP), the callout driver receives process ID directly in
//    `FWPS_INCOMING_VALUES0->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_PROCESS_ID]`.
func (pr *ProcessResolver) resolveWindows(localAddr, remoteAddr string) *ProcessInfo {
	return &ProcessInfo{
		PID:         os.Getpid(),
		Name:        "snitchguard-daemon.exe",
		Path:        `C:\Program Files\SnitchGuard\snitchguard-daemon.exe`,
		CommandLine: `snitchguard-daemon.exe --service`,
		User:        "SYSTEM",
		Signature:   "Microsoft Authenticode Signed",
	}
}

// resolveGenericFallback provides realistic mocked metadata for simulation
func (pr *ProcessResolver) resolveGenericFallback(remoteAddr string) *ProcessInfo {
	return &ProcessInfo{
		PID:         48291,
		Name:        "curl",
		Path:        "/usr/bin/curl",
		CommandLine: "curl -s https://api.github.com/zen",
		User:        "developer",
		Signature:   "OS Packaged Binary",
	}
}
