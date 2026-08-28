/**
 * SnitchGuard - Interactive Connection Alert Window (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState, useEffect } from 'react';
import { ShieldAlert, Globe, Server, Cpu, Check, X, Clock, HelpCircle, Lock, Terminal } from 'lucide-react';
import { ConnectionEvent, FirewallAction, RuleDuration } from '../types/firewall';

interface AlertModalProps {
  alert: ConnectionEvent | null;
  onDecision: (decision: {
    flowId: string;
    action: FirewallAction;
    duration: RuleDuration;
    applyWildcard: boolean;
  }) => void;
  onDismiss: () => void;
}

export const AlertModal: React.FC<AlertModalProps> = ({ alert, onDecision, onDismiss }) => {
  const [applyWildcard, setApplyWildcard] = useState(true);
  const [timeLeft, setTimeLeft] = useState(30);

  useEffect(() => {
    if (!alert) return;
    setTimeLeft(30);
    const interval = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          // Auto-deny on timeout
          onDecision({
            flowId: alert.id,
            action: 'block',
            duration: 'once',
            applyWildcard: false
          });
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [alert, onDecision]);

  if (!alert) return null;

  const getDomainRoot = (domain: string) => {
    if (!domain || domain === 'unknown') return 'domain.com';
    const parts = domain.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return domain;
  };

  const domainRoot = getDomainRoot(alert.domain);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0a0b]/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-[#1e1e21] rounded-2xl border-l-4 border-amber-500 shadow-2xl relative overflow-hidden max-w-xl w-full border-t border-r border-b border-[#27272a]">
        {/* Subtle Watermark Icon */}
        <div className="absolute top-0 right-0 p-3 opacity-5 pointer-events-none rotate-12">
          <ShieldAlert className="w-32 h-32 text-amber-500" />
        </div>

        {/* Card Header */}
        <div className="p-6 pb-2 flex items-center justify-between">
          <div>
            <h3 className="text-amber-500 text-[11px] font-bold uppercase tracking-widest">Pending Connection Request</h3>
            <p className="text-xs text-gray-500">Daemon paused socket until you decide</p>
          </div>
          <div className="flex items-center gap-1.5 text-xs font-mono text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2.5 py-1 rounded-lg">
            <Clock className="w-3.5 h-3.5" />
            <span>{timeLeft}s auto-drop</span>
          </div>
        </div>

        {/* Process & Target Host Hero Section */}
        <div className="px-6 py-3">
          <div className="flex items-start gap-4 p-4 bg-[#141416] rounded-xl border border-[#27272a]">
            <div className="w-12 h-12 bg-white/5 rounded-lg flex items-center justify-center border border-white/10 shrink-0 text-blue-400">
              <Terminal className="w-6 h-6" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-base font-bold text-slate-100 font-mono leading-tight truncate">{alert.processPath || alert.processName}</p>
              <p className="text-xs text-gray-400 mt-1">Attempting to reach:</p>
              <p className="text-sm font-mono text-blue-400 mt-0.5 truncate font-semibold">
                {alert.domain || alert.remoteIP}
              </p>
              <div className="text-[11px] text-gray-500 font-mono mt-1">
                Socket: {alert.remoteIP}:{alert.remotePort} ({alert.protocol.toUpperCase()}) &bull; PID: {alert.pid}
              </div>
            </div>
          </div>
        </div>

        {/* Wildcard Checkbox */}
        <div className="px-6 py-2">
          <div className="bg-[#141416]/60 border border-[#27272a] rounded-xl p-3 flex items-center justify-between">
            <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={applyWildcard}
                onChange={(e) => setApplyWildcard(e.target.checked)}
                className="w-4 h-4 rounded border-gray-700 bg-[#0a0a0b] text-blue-500 focus:ring-blue-500 cursor-pointer"
              />
              <span>
                Apply rule to all subdomains: <code className="text-blue-400 font-mono font-bold">*.{domainRoot}</code>
              </span>
            </label>
            <HelpCircle className="w-3.5 h-3.5 text-gray-600 hidden sm:block" />
          </div>
        </div>

        {/* 4 Decision Buttons Grid */}
        <div className="p-6 pt-3">
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={() => onDecision({ flowId: alert.id, action: 'allow', duration: 'always', applyWildcard })}
              className="bg-emerald-600 hover:bg-emerald-500 text-white py-3 rounded-xl text-xs font-bold transition-all shadow-lg shadow-emerald-950/40 cursor-pointer flex items-center justify-center gap-2"
            >
              <Check className="w-4 h-4" />
              <span>Allow Always</span>
            </button>

            <button
              onClick={() => onDecision({ flowId: alert.id, action: 'allow', duration: 'once', applyWildcard })}
              className="bg-[#2d2d31] hover:bg-[#38383d] text-white py-3 rounded-xl text-xs font-bold border border-white/5 transition cursor-pointer flex items-center justify-center gap-2"
            >
              <Check className="w-4 h-4 text-emerald-400" />
              <span>Allow Once</span>
            </button>

            <button
              onClick={() => onDecision({ flowId: alert.id, action: 'block', duration: 'always', applyWildcard })}
              className="bg-red-600 hover:bg-red-500 text-white py-3 rounded-xl text-xs font-bold transition-all shadow-lg shadow-red-950/40 cursor-pointer flex items-center justify-center gap-2"
            >
              <X className="w-4 h-4" />
              <span>Deny Always</span>
            </button>

            <button
              onClick={() => onDecision({ flowId: alert.id, action: 'block', duration: 'once', applyWildcard })}
              className="bg-[#2d2d31] hover:bg-[#38383d] text-white py-3 rounded-xl text-xs font-bold border border-white/5 transition cursor-pointer flex items-center justify-center gap-2"
            >
              <X className="w-4 h-4 text-red-400" />
              <span>Deny Once</span>
            </button>
          </div>

          <p className="text-[11px] text-gray-500 mt-4 text-center italic">
            A decision is required to proceed with this socket connection.
          </p>
        </div>

        {/* Modal footer dismiss bar */}
        <div className="bg-[#141416] px-6 py-2 border-t border-[#27272a] flex items-center justify-between text-[11px] text-gray-500">
          <span>Neutralino Native Window Pop-up via IPC</span>
          <button onClick={onDismiss} className="hover:text-gray-300 transition underline cursor-pointer">
            Dismiss Prompt
          </button>
        </div>
      </div>
    </div>
  );
};

