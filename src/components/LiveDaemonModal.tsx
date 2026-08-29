/**
 * SnitchGuard - Real Traffic vs Simulation Daemon & Neutralino Packaging Modal
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { X, Activity, Radio, Terminal, Server, CheckCircle2, AlertTriangle, ExternalLink, RefreshCw, Copy, Check, ShieldCheck, Zap, Box, Layers, Play, Database } from 'lucide-react';
import { DaemonConnectionState } from '../types/firewall';
import { neutralinoBridge } from '../services/neutralinoBridge';
import { daemon } from '../services/mockDaemon';

interface LiveDaemonModalProps {
  isOpen: boolean;
  onClose: () => void;
  connectionState: DaemonConnectionState;
  onConnect: (url: string) => void;
  onDisconnect: () => void;
}

export const LiveDaemonModal: React.FC<LiveDaemonModalProps> = ({
  isOpen,
  onClose,
  connectionState,
  onConnect,
  onDisconnect
}) => {
  const [activeTab, setActiveTab] = useState<'packaging' | 'websocket'>('websocket');
  const [daemonUrl, setDaemonUrl] = useState(connectionState.daemonUrl || 'ws://127.0.0.1:9095/ws');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [dataMode, setDataModeState] = useState<'real_daemon' | 'sandbox'>(daemon.getDataSourceMode());

  const nativeStatus = neutralinoBridge.getStatus();
  const isConnected = connectionState.status === 'connected';

  if (!isOpen) return null;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleModeChange = (mode: 'real_daemon' | 'sandbox') => {
    setDataModeState(mode);
    daemon.setDataSourceMode(mode);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0a0b]/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-6 border-b border-[#27272a] flex items-center justify-between bg-[#1c1c1f]">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
              isConnected
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-blue-500/10 border-blue-500/30 text-blue-400'
            }`}>
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-100">Live Kernel Data & Daemon IPC</h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                  isConnected
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                }`}>
                  {isConnected ? 'LIVE DAEMON ACTIVE' : dataMode === 'real_daemon' ? 'REAL DATA MODE (DISCONNECTED)' : 'SANDBOX DEMO'}
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">Neutralinojs Native Desktop App + Elevated Go Firewall Daemon</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-slate-200 hover:bg-[#27272a] rounded-lg transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Subheader Tabs */}
        <div className="flex border-b border-[#27272a] bg-[#141416] px-6">
          <button
            onClick={() => setActiveTab('websocket')}
            className={`flex items-center gap-2 py-3 px-4 text-xs font-bold font-mono border-b-2 transition cursor-pointer ${
              activeTab === 'websocket'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>IPC WebSocket Bridge</span>
          </button>
          <button
            onClick={() => setActiveTab('packaging')}
            className={`flex items-center gap-2 py-3 px-4 text-xs font-bold font-mono border-b-2 transition cursor-pointer ${
              activeTab === 'packaging'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-400 hover:text-slate-200'
            }`}
          >
            <Box className="w-3.5 h-3.5" />
            <span>1-Click Native Packaging</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-gray-300">
          {activeTab === 'websocket' && (
            <>
              {/* Data Source Mode Toggle Card */}
              <div className="bg-[#0a0a0b] border border-[#27272a] rounded-xl p-4 space-y-3">
                <div className="flex items-center gap-2 text-slate-100 font-bold">
                  <Database className="w-4 h-4 text-blue-400" />
                  <span>Data Capture Source Mode</span>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => handleModeChange('real_daemon')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                      dataMode === 'real_daemon'
                        ? 'bg-blue-600/15 border-blue-500 text-slate-100'
                        : 'bg-[#141416] border-[#27272a] text-gray-400 hover:bg-[#1c1c1f]'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold text-xs">
                      <span>Strict Real Data Mode</span>
                      {dataMode === 'real_daemon' && <CheckCircle2 className="w-4 h-4 text-blue-400" />}
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1 leading-relaxed">
                      Zero fake or simulated packets. All socket flows and alerts come strictly from the elevated Go firewall daemon on your host OS.
                    </p>
                  </button>

                  <button
                    onClick={() => handleModeChange('sandbox')}
                    className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                      dataMode === 'sandbox'
                        ? 'bg-amber-500/15 border-amber-500/40 text-slate-100'
                        : 'bg-[#141416] border-[#27272a] text-gray-400 hover:bg-[#1c1c1f]'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold text-xs">
                      <span>Sandbox Demo Mode</span>
                      {dataMode === 'sandbox' && <CheckCircle2 className="w-4 h-4 text-amber-400" />}
                    </div>
                    <p className="text-[11px] text-gray-400 mt-1 leading-relaxed">
                      Generates synthetic socket traffic and test alert modals for offline UI testing when no daemon is active.
                    </p>
                  </button>
                </div>
              </div>

              {/* WebSocket Controller */}
              <div className="bg-[#0a0a0b] border border-[#27272a] rounded-xl p-4 space-y-4">
                <div className="flex items-center justify-between">
                  <label className="font-mono text-gray-400 font-bold uppercase tracking-wider text-[11px]">
                    LOCAL IPC WEBSOCKET ENDPOINT
                  </label>
                  {isConnected && (
                    <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Latency: {connectionState.latencyMs ?? 1}ms</span>
                    </span>
                  )}
                </div>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={daemonUrl}
                    onChange={(e) => setDaemonUrl(e.target.value)}
                    placeholder="ws://127.0.0.1:9095/ws"
                    className="flex-1 bg-[#141416] border border-[#27272a] rounded-xl px-3.5 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
                  />
                  <button
                    onClick={() => onConnect(daemonUrl)}
                    className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold transition cursor-pointer shadow-lg shadow-blue-900/30"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Connect</span>
                  </button>

                  {isConnected && (
                    <button
                      onClick={onDisconnect}
                      className="px-3 py-2 bg-[#1c1c1f] hover:bg-red-500/20 text-red-400 border border-[#27272a] rounded-xl font-bold transition cursor-pointer"
                    >
                      Disconnect
                    </button>
                  )}
                </div>

                {!isConnected && (
                  <div className="p-3 rounded-lg bg-[#141416] border border-[#27272a] text-gray-300 text-[11px] space-y-1">
                    <p className="font-bold text-slate-200">How to launch the elevated Go daemon on your machine:</p>
                    <code className="block bg-[#0a0a0b] p-2 rounded text-emerald-400 font-mono">
                      cd daemon && go run .
                    </code>
                    <p className="text-gray-400 text-[10px]">Or execute <code className="text-blue-400 font-mono">./scripts/run-native.sh</code> to launch both daemon + native desktop app.</p>
                  </div>
                )}
              </div>
            </>
          )}

          {activeTab === 'packaging' && (
            <>
              {/* Packaging Architecture Banner */}
              <div className="bg-[#1c1c1f] border border-[#27272a] rounded-xl p-4 space-y-3">
                <div className="flex items-center gap-2 text-slate-100 font-bold">
                  <Layers className="w-4 h-4 text-blue-400" />
                  <span>How Neutralinojs Bundles Everything into One Native App</span>
                </div>
                <p className="text-gray-400 leading-relaxed text-xs">
                  When you build the project natively, the build script bundles the <strong>Neutralinojs desktop shell</strong> and the <strong>elevated Go daemon binary</strong> into a single unified distribution.
                  When launched, Neutralino automatically starts the Go daemon sidecar, hooks into kernel network sockets (eBPF/WFP/NetworkExtension), and streams <strong>100% real live system traffic</strong> directly into your window.
                </p>
              </div>

              {/* Build Commands */}
              <div>
                <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span>Native Build & Run Commands</span>
                </h4>

                <div className="space-y-3 font-mono text-[11px]">
                  <div className="bg-[#0a0a0b] p-3 rounded-xl border border-[#27272a]">
                    <div className="flex items-center justify-between text-gray-400 mb-1.5">
                      <span className="font-bold text-slate-200">Step 1: Package everything into unified native app</span>
                      <button
                        onClick={() => copyToClipboard('make package', 'cmd-package')}
                        className="text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedCmd === 'cmd-package' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCmd === 'cmd-package' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <code className="text-blue-300">make package</code>
                  </div>

                  <div className="bg-[#0a0a0b] p-3 rounded-xl border border-[#27272a]">
                    <div className="flex items-center justify-between text-gray-400 mb-1.5">
                      <span className="font-bold text-slate-200">Step 2: Run native app with live kernel traffic</span>
                      <button
                        onClick={() => copyToClipboard('make run-native', 'cmd-run')}
                        className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedCmd === 'cmd-run' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCmd === 'cmd-run' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <code className="text-emerald-400">make run-native</code>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#27272a] bg-[#1c1c1f] flex items-center justify-between">
          <a
            href="https://suhail.top"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] text-gray-400 hover:text-blue-400 font-mono inline-flex items-center gap-1"
          >
            Author: Suhail Akhtar
            <ExternalLink className="w-3 h-3" />
          </a>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
