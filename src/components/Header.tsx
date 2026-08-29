/**
 * SnitchGuard - Top Navigation Header (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React from 'react';
import { Shield, Activity, ListFilter, PlayCircle, Cpu, FileCode, Terminal, Sparkles, ShieldAlert, ShieldCheck, Radio, Server, Database } from 'lucide-react';
import { DaemonMetrics } from '../types/firewall';
import { daemon } from '../services/mockDaemon';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  stats: DaemonMetrics;
  isFirewallActive: boolean;
  onToggleFirewall: () => void;
  onOpenChangelog: () => void;
  onQuickSimulate: () => void;
  onOpenLiveModal?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  stats,
  isFirewallActive,
  onToggleFirewall,
  onOpenChangelog,
  onQuickSimulate,
  onOpenLiveModal
}) => {
  const tabs = [
    { id: 'traffic', label: 'Live Traffic', icon: Activity },
    { id: 'rules', label: 'Rule Engine', icon: ListFilter, count: stats.totalRules },
    { id: 'simulator', label: 'Packet Injector', icon: PlayCircle },
    { id: 'ipc', label: 'WebSocket IPC', icon: Terminal },
    { id: 'drivers', label: 'Kernel Drivers', icon: Cpu },
    { id: 'source', label: 'Source Code Tree', icon: FileCode }
  ];

  const isLive = stats.isLiveDaemonConnected;
  const dataMode = daemon.getDataSourceMode();

  const handleToggleDataMode = () => {
    const newMode = dataMode === 'real_daemon' ? 'sandbox' : 'real_daemon';
    daemon.setDataSourceMode(newMode);
  };

  return (
    <header className="bg-[#0a0a0b]/90 backdrop-blur-md border-b border-[#27272a] sticky top-0 z-40">
      {/* Top Banner / System Statusbar */}
      <div className="px-6 py-1.5 bg-[#0a0a0b] border-b border-[#27272a]/60 flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenLiveModal}
            className={`flex items-center gap-2 font-mono text-[11px] px-2 py-0.5 rounded border transition cursor-pointer ${
              isLive
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-[#141416] text-gray-400 border-[#27272a] hover:text-slate-200 hover:border-gray-600'
            }`}
            title="Click to configure Real Go Daemon connection"
          >
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
            <span className="font-bold">{isLive ? 'LIVE KERNEL DAEMON' : 'AWAITING DAEMON'}</span>
            <span className="text-gray-600">|</span>
            <span className="text-gray-400">{stats.daemonUrl || 'ws://127.0.0.1:9095'}</span>
          </button>

          <button
            onClick={handleToggleDataMode}
            className={`flex items-center gap-1.5 px-2 py-0.5 rounded border font-mono text-[11px] transition cursor-pointer ${
              dataMode === 'real_daemon'
                ? 'bg-blue-500/10 text-blue-400 border-blue-500/30 hover:bg-blue-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
            title="Click to switch between Strict Real Data and Sandbox Demo Mode"
          >
            <Database className="w-3 h-3" />
            <span className="font-semibold">{dataMode === 'real_daemon' ? 'MODE: STRICT REAL DATA' : 'MODE: SANDBOX DEMO'}</span>
          </button>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onOpenLiveModal}
            className="flex items-center gap-1.5 text-gray-400 hover:text-blue-400 px-2 py-0.5 rounded transition text-[11px] font-mono hover:bg-[#1c1c1f] cursor-pointer"
          >
            <Server className="w-3 h-3" />
            <span>Connect Daemon</span>
          </button>

          {dataMode === 'sandbox' && (
            <button
              onClick={onQuickSimulate}
              className="flex items-center gap-1.5 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2.5 py-0.5 rounded-md text-[11px] font-medium transition cursor-pointer"
            >
              <Sparkles className="w-3 h-3" />
              <span>Inject Test Alert</span>
            </button>
          )}

          <button
            onClick={onOpenChangelog}
            className="hover:text-gray-300 text-gray-500 px-1.5 py-0.5 rounded transition text-[11px] font-mono hover:bg-[#1c1c1f]"
          >
            {stats.daemonVersion}
          </button>
        </div>
      </div>

      {/* Main Header & Nav Tabs */}
      <div className="px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-900/30">
            <div className="w-5 h-5 border-2 border-white rounded-sm rotate-45 flex items-center justify-center">
              <div className="w-1.5 h-1.5 bg-white rounded-full"></div>
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="font-bold text-lg text-slate-100 tracking-tight">SnitchGuard</h1>
              <p className="text-xs text-gray-500 font-mono hidden sm:inline">Host Application Firewall</p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-[#141416] p-1 rounded-xl border border-[#27272a]">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm'
                    : 'text-gray-400 hover:text-slate-200 hover:bg-[#1c1c1f]'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className="bg-[#27272a] text-gray-300 text-[10px] px-1.5 py-0.2 rounded-full font-mono">
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Firewall Active Status & Toggle */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2.5 bg-[#1c1c1f] px-3.5 py-1.5 rounded-full border border-[#27272a]">
            <div className={`w-2 h-2 rounded-full ${isFirewallActive ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></div>
            <span className={`text-xs font-semibold tracking-wider uppercase ${isFirewallActive ? 'text-emerald-400' : 'text-red-400'}`}>
              {isFirewallActive ? 'Protected' : 'Disabled'}
            </span>
          </div>

          <button
            onClick={onToggleFirewall}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors cursor-pointer border ${
              isFirewallActive
                ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400 border-red-500/30'
                : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
            }`}
          >
            {isFirewallActive ? 'DISABLE FIREWALL' : 'ENABLE FIREWALL'}
          </button>
        </div>
      </div>
    </header>
  );
};

