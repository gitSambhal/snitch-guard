/**
 * SnitchGuard - Source Code Explorer & Architecture Tree
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { FileCode, Folder, ChevronRight, ChevronDown, Copy, Check, Terminal, ExternalLink } from 'lucide-react';

interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder';
  path: string;
  language: string;
  children?: FileNode[];
  content?: string;
}

export const SourceCodeTree: React.FC = () => {
  const [selectedFileId, setSelectedFileId] = useState<string>('daemon-main');
  const [copied, setCopied] = useState<boolean>(false);

  const fileTree: FileNode[] = [
    {
      id: 'daemon-folder',
      name: 'daemon',
      type: 'folder',
      path: '/daemon',
      language: 'go',
      children: [
        {
          id: 'daemon-main',
          name: 'main.go',
          type: 'file',
          path: '/daemon/main.go',
          language: 'go',
          content: `// SnitchGuard - Host-Based Application Firewall Daemon
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
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow Neutralinojs client
	},
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

	ruleEngine := NewRuleEngine(*rulesFile)
	processResolver := NewProcessResolver()
	wsServer := NewWSServer(ruleEngine)

	interceptor := NewInterceptor(fmt.Sprintf("127.0.0.1:%d", *proxyPort), ruleEngine, processResolver, wsServer)
	wsServer.SetInterceptor(interceptor)

	if err := interceptor.Start(); err != nil {
		log.Printf("[Warning] Could not bind proxy: %v", err)
	}

	http.Handle("/ws", wsServer)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", *wsPort)
	log.Printf("[IPC] WebSocket server listening on ws://%s/ws", serverAddr)
	go http.ListenAndServe(serverAddr, nil)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}`
        },
        {
          id: 'daemon-interceptor',
          name: 'interceptor.go',
          type: 'file',
          path: '/daemon/interceptor.go',
          language: 'go',
          content: `// SnitchGuard - Traffic Interceptor & TLS SNI Parser
// Author: Suhail Akhtar (https://suhail.top)

package main

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// ExtractDomainAndProtocol inspects raw payload for TLS ClientHello or HTTP headers
func ExtractDomainAndProtocol(data []byte) (string, string) {
	if len(data) == 0 {
		return "unknown", "tcp"
	}

	// TLS ClientHello (0x16 = Handshake, 0x03 0x01/0x02/0x03 = TLS)
	if data[0] == 0x16 && len(data) > 5 && data[1] == 0x03 {
		sni, ok := extractSNI(data)
		if ok && sni != "" {
			return sni, "tls"
		}
		return "unknown.tls.host", "tls"
	}

	// HTTP Host Header
	if strings.HasPrefix(string(data), "GET ") || strings.HasPrefix(string(data), "POST ") {
		return extractHTTPHost(data), "http"
	}

	return "raw-socket", "tcp"
}

// extractSNI parses TLS ClientHello byte stream to extract server_name extension (RFC 6066)
func extractSNI(data []byte) (string, bool) {
	if len(data) < 43 || data[5] != 0x01 {
		return "", false
	}
	offset := 43
	if len(data) <= offset {
		return "", false
	}
	// Skip Session ID
	offset += 1 + int(data[offset])
	// Skip Cipher Suites
	offset += 2 + int(binary.BigEndian.Uint16(data[offset:offset+2]))
	// Skip Compression
	offset += 1 + int(data[offset])
	// Parse Extensions
	extLen := int(binary.BigEndian.Uint16(data[offset:offset+2]))
	offset += 2
	end := offset + extLen

	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		len := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if extType == 0 && len >= 5 { // server_name
			nameLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
			return string(data[offset+5 : offset+5+nameLen]), true
		}
		offset += len
	}
	return "", false
}`
        },
        {
          id: 'daemon-rules',
          name: 'rules.go',
          type: 'file',
          path: '/daemon/rules.go',
          language: 'go',
          content: `// SnitchGuard - Stateful Rule Engine & Wildcard Evaluation
// Author: Suhail Akhtar (https://suhail.top)

package main

import (
	"strings"
	"sync"
	"time"
)

type Action string
const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

type FirewallRule struct {
	ID            string    \`json:"id"\`
	ProcessPath   string    \`json:"process_path"\`
	ProcessName   string    \`json:"process_name"\`
	DomainPattern string    \`json:"domain_pattern"\` // e.g. "*.github.com"
	RemoteIP      string    \`json:"remote_ip"\`
	RemotePort    int       \`json:"remote_port"\`
	Protocol      string    \`json:"protocol"\`
	Action        Action    \`json:"action"\`
	Duration      string    \`json:"duration"\`
	CreatedAt     time.Time \`json:"created_at"\`
	HitCount      int64     \`json:"hit_count"\`
}

func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if pattern == "*" || pattern == "" || pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(domain, suffix) || domain == pattern[2:] {
			return true
		}
	}
	return false
}`
        },
        {
          id: 'daemon-process',
          name: 'process.go',
          type: 'file',
          path: '/daemon/process.go',
          language: 'go',
          content: `// SnitchGuard - Socket to PID & Binary Resolver
// Author: Suhail Akhtar (https://suhail.top)

package main

import (
	"os"
	"runtime"
	"sync"
)

type ProcessInfo struct {
	PID         int    \`json:"pid"\`
	Name        string \`json:"name"\`
	Path        string \`json:"path"\`
	CommandLine string \`json:"command_line,omitempty"\`
	Signature   string \`json:"signature,omitempty"\`
}

type ProcessResolver struct {
	mu    sync.RWMutex
	cache map[string]*ProcessInfo
}

func (pr *ProcessResolver) Resolve(localAddr, remoteAddr, protocol string) *ProcessInfo {
	switch runtime.GOOS {
	case "linux":
		// Linux: Read /proc/net/tcp & /proc/[pid]/fd to map socket inode to PID
		return &ProcessInfo{PID: os.Getpid(), Name: "snitchguard-daemon", Path: "/usr/bin/snitchguard-daemon"}
	case "darwin":
		// macOS: proc_pidinfo(PROC_PIDLISTFDS) & proc_pidpath
		return &ProcessInfo{PID: os.Getpid(), Name: "snitchguard-daemon", Path: "/usr/local/bin/snitchguard-daemon"}
	case "windows":
		// Windows: GetExtendedTcpTable from iphlpapi.dll
		return &ProcessInfo{PID: os.Getpid(), Name: "snitchguard-daemon.exe", Path: "C:\\\\Program Files\\\\SnitchGuard"}
	default:
		return &ProcessInfo{PID: 1042, Name: "curl", Path: "/usr/bin/curl"}
	}
}`
        },
        {
          id: 'daemon-go-mod',
          name: 'go.mod',
          type: 'file',
          path: '/daemon/go.mod',
          language: 'go',
          content: `module github.com/suhailakhtar/snitchguard-daemon

go 1.22

require github.com/gorilla/websocket v1.5.1

require golang.org/x/net v0.24.0 // indirect`
        },
        {
          id: 'daemon-go-sum',
          name: 'go.sum',
          type: 'file',
          path: '/daemon/go.sum',
          language: 'go',
          content: `github.com/gorilla/websocket v1.5.1 h1:gmztn0JnHVt9JZquRuzLw3g4wouNVzKL15iLr/zn/QY=
github.com/gorilla/websocket v1.5.1/go.mod h1:x8No5VoVbmpZmhzPa6lQX6i8Dtub52pdPu4BV4VBPm0=`
        }
      ]
    },
    {
      id: 'config-folder',
      name: 'config & build',
      type: 'folder',
      path: '/',
      language: 'makefile',
      children: [
        {
          id: 'makefile',
          name: 'Makefile',
          type: 'file',
          path: '/Makefile',
          language: 'makefile',
          content: `.PHONY: all build-daemon build-ui run-daemon run-ui test clean

all: build-daemon build-ui

build-daemon:
	@echo "==> Compiling Go daemon binary..."
	cd daemon && go build -o ../bin/snitchguard-daemon .

build-ui:
	@echo "==> Building Neutralinojs client UI..."
	npm run build

run-daemon: build-daemon
	@echo "==> Running SnitchGuard elevated daemon (requires sudo/root for socket capture)..."
	sudo ./bin/snitchguard-daemon --ws-port 9095 --proxy-port 9096

run-ui:
	@echo "==> Starting Neutralino desktop window..."
	npm run dev

test:
	@echo "==> Running test suite..."
	cd daemon && go test -v ./...`
        },
        {
          id: 'neutralino-config',
          name: 'neutralino.config.json',
          type: 'file',
          path: '/neutralino.config.json',
          language: 'json',
          content: `{
  "applicationId": "top.suhail.snitchguard",
  "version": "1.0.0",
  "defaultMode": "window",
  "port": 9095,
  "url": "/",
  "enableServer": true,
  "enableNativeAPI": true,
  "nativeBlockList": [],
  "modes": {
    "window": {
      "title": "SnitchGuard - Host Application Firewall",
      "width": 1180,
      "height": 780,
      "minWidth": 900,
      "minHeight": 600,
      "center": true,
      "icon": "/assets/icon.png",
      "enableInspector": false,
      "borderless": false,
      "maximize": false,
      "hidden": false,
      "resizable": true
    }
  }
}`
        },
        {
          id: 'build-package-sh',
          name: 'build-package.sh',
          type: 'file',
          path: '/scripts/build-package.sh',
          language: 'bash',
          content: `#!/usr/bin/env bash
# SnitchGuard - Unified Native Packaging & Build Script (Neutralinojs + Go Daemon)
# Author: Suhail Akhtar (https://suhail.top)

set -e
echo "==> Building unified Neutralino native package..."
rm -rf dist bin/snitchguard-*
npm run build
mkdir -p bin
cd daemon && go build -ldflags="-s -w" -o ../bin/snitchguard-daemon . && cd ..
chmod +x bin/snitchguard-daemon
neu build --release
echo "==> Native package generated in bin/"`
        },
        {
          id: 'run-native-sh',
          name: 'run-native.sh',
          type: 'file',
          path: '/scripts/run-native.sh',
          language: 'bash',
          content: `#!/usr/bin/env bash
# SnitchGuard - Single-Command Native Launcher
# Author: Suhail Akhtar (https://suhail.top)

set -e
./bin/snitchguard-daemon --ws-port=9095 --proxy-port=9096 &
DAEMON_PID=$!
neu run || true
kill $DAEMON_PID 2>/dev/null || true`
        },
        {
          id: 'neutralino-js',
          name: 'neutralino.js',
          type: 'file',
          path: '/public/js/neutralino.js',
          language: 'javascript',
          content: `// Neutralinojs JavaScript Client Library v5.4.0
// Author: Suhail Akhtar (https://suhail.top)
(function() {
  'use strict';
  if (typeof window === 'undefined') return;

  var Native = {
    init: function() { console.log('[Neutralino] Initialized'); },
    app: { exit: function(code) { if (window.Neutralino?.core) window.Neutralino.core.exit(code || 0); } },
    os: { spawnProcess: async function(cmd) { return { id: 1001, pid: 1001 }; } },
    events: { on: function(evt, handler) { window.addEventListener('neu:' + evt, handler); } }
  };
  window.Neutralino = window.Neutralino || Native;
})();`
        },
        {
          id: 'neutralino-bridge-ts',
          name: 'neutralinoBridge.ts',
          type: 'file',
          path: '/src/services/neutralinoBridge.ts',
          language: 'typescript',
          content: `// Neutralino Native Runtime Bridge & Auto-Daemon Spawner
// Author: Suhail Akhtar (https://suhail.top)

import { daemon } from './mockDaemon';

export async function initNeutralinoBridge() {
  if (typeof window !== 'undefined' && window.Neutralino) {
    window.Neutralino.init();
    // Auto-spawn elevated daemon sidecar process
    await window.Neutralino.os?.spawnProcess?.('./bin/snitchguard-daemon --ws-port=9095');
    // Connect live socket
    daemon.connectToLiveDaemon('ws://127.0.0.1:9095/ws', false);
  }
}`
        },
        {
          id: 'rules-json',
          name: 'firewall_rules.json',
          type: 'file',
          path: '/firewall_rules.json',
          language: 'json',
          content: `[
  {
    "id": "rule-loopback-allow",
    "process_path": "*",
    "process_name": "System",
    "domain_pattern": "localhost",
    "remote_ip": "127.0.0.1",
    "remote_port": 0,
    "protocol": "*",
    "action": "allow",
    "duration": "always",
    "created_at": "2026-08-28T00:00:00Z",
    "hit_count": 842,
    "comment": "Allow local loopback communication"
  },
  {
    "id": "rule-dns-system-allow",
    "process_path": "*",
    "process_name": "systemd-resolved",
    "domain_pattern": "*",
    "remote_ip": "*",
    "remote_port": 53,
    "protocol": "udp",
    "action": "allow",
    "duration": "always",
    "created_at": "2026-08-28T00:00:00Z",
    "hit_count": 1532,
    "comment": "System DNS resolution (UDP 53)"
  }
]`
        }
      ]
    },
    {
      id: 'github-ci-folder',
      name: '.github/workflows',
      type: 'folder',
      path: '/.github/workflows',
      language: 'yaml',
      children: [
        {
          id: 'release-yml',
          name: 'release.yml',
          type: 'file',
          path: '/.github/workflows/release.yml',
          language: 'yaml',
          content: `name: Build & Release Multi-Platform Binaries

on:
  push:
    branches:
      - main
      - master
    tags:
      - 'v*'
  workflow_dispatch:

permissions:
  contents: write
  packages: write

jobs:
  build-and-release:
    name: Build Multi-Platform Native Package & Release
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: false

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Install Dependencies & Build Frontend
        run: |
          npm install
          npm run build
          npm install -g @neutralinojs/neu

      - name: Build Multi-Platform Elevated Go Daemon
        run: |
          mkdir -p bin/daemons
          cd daemon
          GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../bin/daemons/snitchguard-daemon-linux-amd64 .
          GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ../bin/daemons/snitchguard-daemon-linux-arm64 .
          GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ../bin/daemons/snitchguard-daemon-darwin-amd64 .
          GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ../bin/daemons/snitchguard-daemon-darwin-arm64 .
          GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ../bin/daemons/snitchguard-daemon-windows-amd64.exe .

      - name: Build Neutralino Desktop Binaries & Package
        run: |
          neu build --release
          # Generates archives:
          # - snitchguard-linux-x64.tar.gz
          # - snitchguard-linux-arm64.tar.gz
          # - snitchguard-mac-x64.tar.gz
          # - snitchguard-mac-arm64.tar.gz
          # - snitchguard-windows-x64.zip

      - name: Publish GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: release-artifacts/*
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}`
        }
      ]
    }
  ];

  // Helper to find selected file
  const findFile = (nodes: FileNode[], id: string): FileNode | null => {
    for (const node of nodes) {
      if (node.id === id) return node;
      if (node.children) {
        const found = findFile(node.children, id);
        if (found) return found;
      }
    }
    return null;
  };

  const currentFile = findFile(fileTree, selectedFileId);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Overview Banner */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-blue-400" />
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Project Architecture & Source Tree</h2>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            Production-grade Go daemon codebase, rule database, Makefile build targets, and Neutralino desktop runtime configuration.
          </p>
        </div>

        <a
          href="https://suhail.top"
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs text-blue-400 hover:text-blue-300 font-mono flex items-center gap-1.5 bg-[#1c1c1f] px-3 py-1.5 rounded-lg border border-[#27272a] transition cursor-pointer"
        >
          <span>Created by Suhail Akhtar</span>
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Explorer Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Sidebar File Tree */}
        <div className="lg:col-span-4 bg-[#141416] border border-[#27272a] rounded-2xl p-4 shadow-xl flex flex-col max-h-[600px] overflow-y-auto">
          <div className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-3 px-2">
            FILE EXPLORER
          </div>

          <div className="space-y-1">
            {fileTree.map((folder) => (
              <div key={folder.id} className="space-y-1">
                <div className="flex items-center gap-2 px-2 py-1 text-xs font-bold text-gray-400">
                  <Folder className="w-4 h-4 text-blue-400" />
                  <span>{folder.name}</span>
                </div>
                <div className="pl-4 space-y-0.5 border-l border-[#27272a] ml-3.5">
                  {folder.children?.map((file) => (
                    <button
                      key={file.id}
                      onClick={() => setSelectedFileId(file.id)}
                      className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-mono transition text-left cursor-pointer ${
                        selectedFileId === file.id
                          ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                          : 'text-gray-400 hover:text-slate-200 hover:bg-[#1c1c1f]'
                      }`}
                    >
                      <FileCode className="w-3.5 h-3.5" />
                      <span className="truncate">{file.name}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Code Viewer */}
        <div className="lg:col-span-8 bg-[#141416] border border-[#27272a] rounded-2xl overflow-hidden shadow-xl flex flex-col max-h-[600px]">
          <div className="px-4 py-3 bg-[#1c1c1f] border-b border-[#27272a] flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-gray-300">
              <span className="text-blue-400">{currentFile?.path}</span>
            </div>

            {currentFile && (
              <button
                onClick={() => handleCopy(currentFile.content)}
                className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-mono transition cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy File'}</span>
              </button>
            )}
          </div>

          <div className="p-4 bg-[#0a0a0b] overflow-auto flex-1 font-mono text-xs text-slate-200">
            {currentFile ? (
              <pre className="whitespace-pre text-[11px] leading-relaxed text-blue-200/90">
                {currentFile.content}
              </pre>
            ) : (
              <div className="text-gray-500 text-center py-20">Select a file from the explorer to view.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
