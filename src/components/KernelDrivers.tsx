/**
 * SnitchGuard - Kernel Drivers & OS Interception Architecture
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { Cpu, Shield, Layers, Terminal, CheckCircle2, ArrowRight, Code2, Copy, Check } from 'lucide-react';

export const KernelDrivers: React.FC = () => {
  const [activePlatform, setActivePlatform] = useState<'linux' | 'macos' | 'windows'>('linux');
  const [copied, setCopied] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const ebpfCode = `// SnitchGuard eBPF TC Filter (Linux Kernel 5.4+)
// Hooks into cls_act and evaluates socket cookies
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // socket cookie
    __type(value, __u32); // verdict: 1=allow, 2=drop, 3=divert
} flow_verdicts SEC(".maps");

SEC("tc_egress")
int handle_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    __u64 sock_cookie = bpf_get_socket_cookie(skb);
    __u32 *verdict = bpf_map_lookup_elem(&flow_verdicts, &sock_cookie);

    if (verdict && *verdict == 2) {
        return TC_ACT_SHOT; // Drop packet immediately in kernel
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";`;

  const macExtensionCode = `// SnitchGuard macOS NetworkExtension (NEFilterDataProvider)
// System Extension running with root entitlement
import NetworkExtension

class SnitchGuardFilterProvider: NEFilterDataProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let rules = [NEFilterRule(networkRule: NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        ), action: .filterData)]
        
        let settings = NEFilterSettings(rules: rules, defaultAction: .filterData)
        apply(settings) { error in
            completionHandler(error)
        }
    }

    override func handleNewFlow(_ flow: NEFilterSocketFlow) -> NEFilterNewFlowVerdict {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }
        
        // Extract process audit token and query daemon IPC
        let pid = flow.processAuditToken?.pid
        let destHost = flow.remoteHostname ?? remoteEndpoint.hostname
        
        // Pass verdict to Go daemon
        return .needRules() // Pause connection until user decision
    }
}`;

  const wfpCode = `// SnitchGuard Windows Filtering Platform (WFP Kernel Callout)
// FWPM_LAYER_ALE_AUTH_CONNECT_V4
#include <ntddk.h>
#include <fwpsk.h>

VOID NTAPI SnitchGuardConnectClassify(
    IN const FWPS_INCOMING_VALUES0* inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN OUT VOID* layerData,
    IN const VOID* classifyContext,
    IN const FWPS_FILTER3* filter,
    IN UINT64 flowContext,
    OUT FWPS_CLASSIFY_OUT0* classifyOut
) {
    UINT64 processId = inMetaValues->processId;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    // Check pre-approved ring buffer table
    if (IsProcessBlocked(processId)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
}`;

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-6 shadow-xl">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Kernel Driver Architecture & Interception Planes</h2>
            <p className="text-xs text-gray-500">How SnitchGuard hooks into operating system network stacks across Linux, macOS, and Windows</p>
          </div>
        </div>

        {/* Platform Selector */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => setActivePlatform('linux')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition cursor-pointer flex items-center gap-2 border ${
              activePlatform === 'linux'
                ? 'bg-blue-600/15 text-blue-400 border-blue-500/30'
                : 'bg-[#1c1c1f] text-gray-400 border-[#27272a] hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Linux (eBPF / cgroup2 / TC)</span>
          </button>

          <button
            onClick={() => setActivePlatform('macos')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition cursor-pointer flex items-center gap-2 border ${
              activePlatform === 'macos'
                ? 'bg-blue-600/15 text-blue-400 border-blue-500/30'
                : 'bg-[#1c1c1f] text-gray-400 border-[#27272a] hover:text-slate-200'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>macOS (NetworkExtension)</span>
          </button>

          <button
            onClick={() => setActivePlatform('windows')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition cursor-pointer flex items-center gap-2 border ${
              activePlatform === 'windows'
                ? 'bg-blue-600/15 text-blue-400 border-blue-500/30'
                : 'bg-[#1c1c1f] text-gray-400 border-[#27272a] hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Windows (WFP Callout)</span>
          </button>
        </div>
      </div>

      {/* Architecture Visual & Explanation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-5 shadow-xl">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">Packet Lifecycle & Decision Pipeline</h3>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-[#1c1c1f] rounded-xl border border-[#27272a] flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-[11px] shrink-0">1</span>
                <div>
                  <p className="font-bold text-slate-200">Socket Creation & `connect()`</p>
                  <p className="text-gray-500 text-[11px] mt-0.5">Application issues standard `connect()` syscall to target IP/port.</p>
                </div>
              </div>

              <div className="p-3 bg-[#1c1c1f] rounded-xl border border-[#27272a] flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-[11px] shrink-0">2</span>
                <div>
                  <p className="font-bold text-blue-400">Kernel Trap & Flow Redirection</p>
                  <p className="text-gray-500 text-[11px] mt-0.5">Kernel hook traps the outbound SYN packet and holds socket in unapproved state.</p>
                </div>
              </div>

              <div className="p-3 bg-[#1c1c1f] rounded-xl border border-[#27272a] flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold text-[11px] shrink-0">3</span>
                <div>
                  <p className="font-bold text-purple-400">SNI Extraction & PID Lookup</p>
                  <p className="text-gray-500 text-[11px] mt-0.5">Go daemon parses initial ClientHello TLS buffer (RFC 6066) to discover destination domain.</p>
                </div>
              </div>

              <div className="p-3 bg-[#1c1c1f] rounded-xl border border-[#27272a] flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-[11px] shrink-0">4</span>
                <div>
                  <p className="font-bold text-amber-400">WebSocket IPC Alert to UI</p>
                  <p className="text-gray-500 text-[11px] mt-0.5">If no matching rule exists in `firewall_rules.json`, pop up interactive decision window.</p>
                </div>
              </div>

              <div className="p-3 bg-[#1c1c1f] rounded-xl border border-[#27272a] flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-[11px] shrink-0">5</span>
                <div>
                  <p className="font-bold text-emerald-400">Verdict Enforcement</p>
                  <p className="text-gray-500 text-[11px] mt-0.5">Daemon pipes bidirectional traffic or immediately sends TCP RST / drops socket.</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Code Snippet Box */}
        <div className="lg:col-span-7 bg-[#141416] border border-[#27272a] rounded-2xl overflow-hidden shadow-xl flex flex-col">
          <div className="p-3.5 bg-[#1c1c1f] border-b border-[#27272a] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Code2 className="w-4 h-4 text-blue-400" />
              <span className="text-xs font-bold text-gray-300 font-mono">
                {activePlatform === 'linux' && 'ebpf/filter.c'}
                {activePlatform === 'macos' && 'extension/FilterProvider.swift'}
                {activePlatform === 'windows' && 'driver/callout.c'}
              </span>
            </div>

            <button
              onClick={() => {
                const code = activePlatform === 'linux' ? ebpfCode : activePlatform === 'macos' ? macExtensionCode : wfpCode;
                handleCopy(code, 'driver-code');
              }}
              className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 font-mono transition cursor-pointer"
            >
              {copied === 'driver-code' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied === 'driver-code' ? 'Copied' : 'Copy Driver Code'}</span>
            </button>
          </div>

          <div className="p-4 bg-[#0a0a0b] overflow-x-auto flex-1 font-mono text-xs text-slate-200">
            <pre className="whitespace-pre text-[11px] leading-relaxed text-blue-300">
              {activePlatform === 'linux' && ebpfCode}
              {activePlatform === 'macos' && macExtensionCode}
              {activePlatform === 'windows' && wfpCode}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
