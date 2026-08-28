/**
 * SnitchGuard - Active Live Traffic Monitor (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { Activity, Search, Trash2, ShieldOff, CheckCircle2, ArrowUpRight, ArrowDownLeft, Ban } from 'lucide-react';
import { ConnectionEvent, FirewallAction } from '../types/firewall';

interface TrafficMonitorProps {
  traffic: ConnectionEvent[];
  onClear: () => void;
  onBlockProcess: (processName: string) => void;
  onAllowProcess: (processName: string) => void;
}

export const TrafficMonitor: React.FC<TrafficMonitorProps> = ({
  traffic,
  onClear,
  onBlockProcess,
  onAllowProcess
}) => {
  const [filterText, setFilterText] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [stateFilter, setStateFilter] = useState<string>('all');

  const filteredTraffic = traffic.filter((item) => {
    const matchesText =
      !filterText ||
      item.processName.toLowerCase().includes(filterText.toLowerCase()) ||
      item.domain.toLowerCase().includes(filterText.toLowerCase()) ||
      item.remoteIP.includes(filterText) ||
      item.pid.toString().includes(filterText);

    const matchesProto = protocolFilter === 'all' || item.protocol === protocolFilter;
    const matchesState = stateFilter === 'all' || item.state === stateFilter;

    return matchesText && matchesProto && matchesState;
  });

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const getProcessIconBadge = (name: string) => {
    const lower = name.toLowerCase();
    if (lower.includes('chrome')) return { text: 'CH', bg: 'bg-orange-500/20 text-orange-400' };
    if (lower.includes('spotify')) return { text: 'SP', bg: 'bg-emerald-500/20 text-emerald-400' };
    if (lower.includes('code') || lower.includes('vscode')) return { text: 'VS', bg: 'bg-blue-500/20 text-blue-400' };
    if (lower.includes('docker')) return { text: 'DK', bg: 'bg-cyan-500/20 text-cyan-400' };
    if (lower.includes('curl')) return { text: 'CL', bg: 'bg-indigo-500/20 text-indigo-400' };
    if (lower.includes('python')) return { text: 'PY', bg: 'bg-amber-500/20 text-amber-400' };
    if (lower.includes('git')) return { text: 'GT', bg: 'bg-rose-500/20 text-rose-400' };
    return { text: name.substring(0, 2).toUpperCase(), bg: 'bg-gray-500/20 text-gray-300' };
  };

  const totalTx = traffic.reduce((acc, t) => acc + (t.bytesSent || 0), 0);
  const totalRx = traffic.reduce((acc, t) => acc + (t.bytesRecv || 0), 0);

  return (
    <div className="flex flex-col gap-4">
      {/* Section Header & Rates */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-widest text-gray-400">Active Network Traffic</h3>
          <p className="text-[11px] text-gray-500">Real-time socket flows inspected via kernel hooks</p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono bg-blue-500/10 text-blue-400 px-2.5 py-1 rounded-lg border border-blue-500/20 flex items-center gap-1">
            <ArrowUpRight className="w-3 h-3" />
            <span>UP: {(totalTx / 1024).toFixed(1)} KB/s</span>
          </span>
          <span className="text-[11px] font-mono bg-purple-500/10 text-purple-400 px-2.5 py-1 rounded-lg border border-purple-500/20 flex items-center gap-1">
            <ArrowDownLeft className="w-3 h-3" />
            <span>DOWN: {(totalRx / 1024).toFixed(1)} KB/s</span>
          </span>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 flex-1 min-w-[260px]">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder="Search by process, PID, destination domain..."
              className="w-full bg-[#1c1c1f] border border-[#27272a] focus:border-blue-500 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none transition"
            />
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-[#1c1c1f] border border-[#27272a] text-gray-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
          >
            <option value="all">All Protocols</option>
            <option value="tls">TLS (SNI)</option>
            <option value="http">HTTP</option>
            <option value="tcp">Raw TCP</option>
            <option value="udp">UDP</option>
          </select>

          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="bg-[#1c1c1f] border border-[#27272a] text-gray-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
          >
            <option value="all">All States</option>
            <option value="allowed">Allowed</option>
            <option value="blocked">Blocked</option>
            <option value="pending">Pending</option>
          </select>
        </div>

        <button
          onClick={onClear}
          className="flex items-center gap-1.5 bg-[#1c1c1f] hover:bg-[#27272a] text-gray-400 hover:text-gray-200 border border-[#27272a] px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
        >
          <Trash2 className="w-3 h-3" />
          <span>Clear Log</span>
        </button>
      </div>

      {/* Traffic Table Card */}
      <div className="bg-[#141416] rounded-2xl border border-[#27272a] overflow-hidden flex flex-col shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#27272a] bg-[#1c1c1f]">
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider">Process / App</th>
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider">Destination Host</th>
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider">Socket / Proto</th>
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider">Bandwidth & Activity</th>
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider">Status</th>
                <th className="p-3.5 text-[11px] font-bold text-gray-500 uppercase tracking-wider text-right">Action</th>
              </tr>
            </thead>
            <tbody className="text-sm divide-y divide-[#27272a]">
              {filteredTraffic.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-xs text-gray-500">
                    No active network sockets captured yet.
                  </td>
                </tr>
              ) : (
                filteredTraffic.map((conn) => {
                  const badge = getProcessIconBadge(conn.processName);
                  const isBlocked = conn.state === 'blocked';
                  const isAllowed = conn.state === 'allowed';
                  const isPending = conn.state === 'pending';

                  // calculate dummy activity ratio for progress bar
                  const total = (conn.bytesSent || 0) + (conn.bytesRecv || 0);
                  const activityPct = Math.min(100, Math.max(15, Math.round((total / 50000) * 100)));

                  return (
                    <tr key={conn.id} className="hover:bg-white/[0.02] transition">
                      {/* Process & PID */}
                      <td className="p-3.5">
                        <div className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs font-mono ${badge.bg}`}>
                            {badge.text}
                          </div>
                          <div>
                            <p className="font-medium text-slate-200 text-xs">{conn.processName}</p>
                            <p className="text-[10px] text-gray-500 font-mono">PID {conn.pid}</p>
                          </div>
                        </div>
                      </td>

                      {/* Destination Host (SNI) */}
                      <td className="p-3.5 font-mono text-xs text-blue-400">
                        <div className="truncate max-w-[240px] font-medium" title={conn.domain || conn.remoteIP}>
                          {conn.domain || conn.remoteIP}
                        </div>
                        <div className="text-[10px] text-gray-500">{conn.remoteIP}:{conn.remotePort}</div>
                      </td>

                      {/* Protocol */}
                      <td className="p-3.5">
                        <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#1c1c1f] text-gray-300 border border-[#27272a]">
                          {conn.protocol}
                        </span>
                      </td>

                      {/* Bandwidth & Activity Progress */}
                      <td className="p-3.5">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-[10px] font-mono text-gray-400">
                            <span>{formatBytes(conn.bytesSent)} &uarr;</span>
                            <span>{formatBytes(conn.bytesRecv)} &darr;</span>
                          </div>
                          <div className="w-28 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                isBlocked ? 'bg-red-500' : isPending ? 'bg-amber-500' : 'bg-blue-500'
                              }`}
                              style={{ width: `${isBlocked ? 100 : activityPct}%` }}
                            ></div>
                          </div>
                        </div>
                      </td>

                      {/* Status Verdict */}
                      <td className="p-3.5">
                        {isAllowed && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase tracking-wide">
                            <CheckCircle2 className="w-3 h-3" /> ALLOWED
                          </span>
                        )}
                        {isBlocked && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/20 uppercase tracking-wide">
                            <ShieldOff className="w-3 h-3" /> BLOCKED
                          </span>
                        )}
                        {isPending && (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse uppercase tracking-wide">
                            PROMPT
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="p-3.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => onBlockProcess(conn.processName)}
                            className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 px-2.5 py-1 rounded text-[10px] font-semibold transition cursor-pointer"
                            title="Block process from all future network access"
                          >
                            Block App
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer Stats */}
        <div className="p-3.5 border-t border-[#27272a] bg-[#1c1c1f]/50 flex items-center justify-between text-xs">
          <span className="text-[11px] text-gray-500 font-mono">
            Showing {filteredTraffic.length} active socket connections
          </span>
          <div className="flex items-center gap-3 text-[11px]">
            <span className="text-gray-500">Kernel Hook: eBPF TC egress</span>
          </div>
        </div>
      </div>
    </div>
  );
};

