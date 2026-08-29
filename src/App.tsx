/**
 * SnitchGuard - Cross-Platform Host Application Firewall
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { TrafficMonitor } from './components/TrafficMonitor';
import { RuleManager } from './components/RuleManager';
import { TrafficSimulator } from './components/TrafficSimulator';
import { IpcInspector } from './components/IpcInspector';
import { KernelDrivers } from './components/KernelDrivers';
import { SourceCodeTree } from './components/SourceCodeTree';
import { AlertModal } from './components/AlertModal';
import { ChangelogModal } from './components/ChangelogModal';
import { LiveDaemonModal } from './components/LiveDaemonModal';
import { daemon } from './services/mockDaemon';
import { neutralinoBridge } from './services/neutralinoBridge';
import { FirewallRule, ConnectionEvent, DaemonMetrics, FirewallAction, RuleDuration, DaemonConnectionState } from './types/firewall';
import { Activity, Shield, ShieldAlert, ShieldCheck, Cpu, Terminal, ArrowUpRight, ArrowDownLeft, Zap, Info, CheckCircle2, X } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('traffic');
  const [rules, setRules] = useState<FirewallRule[]>(daemon.getRules());
  const [traffic, setTraffic] = useState<ConnectionEvent[]>(daemon.getTraffic());
  const [stats, setStats] = useState<DaemonMetrics>(daemon.getStats());
  const [pendingAlert, setPendingAlert] = useState<ConnectionEvent | null>(daemon.getPendingAlert());
  const [connectionState, setConnectionState] = useState<DaemonConnectionState>(daemon.getConnectionState());
  const [isFirewallActive, setIsFirewallActive] = useState<boolean>(true);
  const [isChangelogOpen, setIsChangelogOpen] = useState<boolean>(false);
  const [isLiveModalOpen, setIsLiveModalOpen] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<{ id: string; text: string; type: 'success' | 'info' | 'error' } | null>(null);

  // Subscribe to stateful daemon and native bridge updates
  useEffect(() => {
    const unsubDaemon = daemon.subscribe(() => {
      setRules([...daemon.getRules()]);
      setTraffic([...daemon.getTraffic()]);
      setStats({ ...daemon.getStats() });
      setPendingAlert(daemon.getPendingAlert());
      setConnectionState({ ...daemon.getConnectionState() });
    });

    const unsubBridge = neutralinoBridge.subscribe((status) => {
      if (status.isNeutralino) {
        showToast('Neutralino Native Runtime Detected: Live Host Traffic Active', 'success');
      }
    });

    return () => {
      unsubDaemon();
      unsubBridge();
    };
  }, []);

  const showToast = (text: string, type: 'success' | 'info' | 'error' = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToastMessage({ id, text, type });
    setTimeout(() => {
      setToastMessage((prev) => (prev?.id === id ? null : prev));
    }, 3500);
  };

  const handleDecision = (decision: {
    flowId: string;
    action: FirewallAction;
    duration: RuleDuration;
    applyWildcard: boolean;
  }) => {
    daemon.submitDecision(decision);
    showToast(
      `Decision applied: ${decision.action.toUpperCase()} for ${decision.duration} duration.`,
      decision.action === 'allow' ? 'success' : 'error'
    );
  };

  const handleAddRule = (rule: Partial<FirewallRule>) => {
    daemon.addRule(rule);
    showToast(`Added new firewall rule for "${rule.processName || '*'} -> ${rule.domainPattern || '*'}"`, 'success');
  };

  const handleDeleteRule = (id: string) => {
    daemon.deleteRule(id);
    showToast('Firewall rule removed successfully.', 'info');
  };

  const handleSimulate = (req: {
    processName: string;
    processPath?: string;
    domain: string;
    remoteIP: string;
    port: number;
    protocol: 'tls' | 'http' | 'tcp' | 'udp';
  }) => {
    daemon.simulateConnection(req);
    showToast(`Injected connection for ${req.processName} -> ${req.domain}`, 'info');
  };

  const handleBlockProcess = (processName: string) => {
    daemon.addRule({
      processName,
      processPath: `/usr/bin/${processName}`,
      domainPattern: '*',
      remoteIP: '*',
      remotePort: 0,
      protocol: '*',
      action: 'block',
      duration: 'always',
      comment: `Instant block for process ${processName}`
    });
    showToast(`Permanently blocked network access for process "${processName}"`, 'error');
  };

  const handleAllowProcess = (processName: string) => {
    daemon.addRule({
      processName,
      processPath: `/usr/bin/${processName}`,
      domainPattern: '*',
      remoteIP: '*',
      remotePort: 0,
      protocol: '*',
      action: 'allow',
      duration: 'always',
      comment: `Instant allow for process ${processName}`
    });
    showToast(`Permanently allowed network access for process "${processName}"`, 'success');
  };

  const handleQuickSimulateAlert = () => {
    daemon.simulateConnection({
      processName: 'telemetry-beacon',
      processPath: '/opt/analytics/telemetry-beacon',
      domain: 'track-user-data.spyware-cdn.io',
      remoteIP: '198.51.100.44',
      port: 443,
      protocol: 'tls'
    });
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="min-h-screen bg-[#0a0a0b] text-slate-100 flex flex-col selection:bg-blue-500/20 selection:text-blue-200">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        stats={stats}
        isFirewallActive={isFirewallActive}
        onToggleFirewall={() => {
          const nextState = !isFirewallActive;
          setIsFirewallActive(nextState);
          daemon.setFirewallEnabled(nextState);
          showToast(`Firewall ${nextState ? 'ENABLED' : 'DISABLED'}`, nextState ? 'success' : 'error');
        }}
        onOpenChangelog={() => setIsChangelogOpen(true)}
        onQuickSimulate={handleQuickSimulateAlert}
        onOpenLiveModal={() => setIsLiveModalOpen(true)}
      />

      {/* Hero Stats Banner */}
      <div className="border-b border-[#27272a] bg-[#141416]/40 px-6 py-4">
        <div className="max-w-7xl mx-auto grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* Card 1: Active Socket Flows */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>ACTIVE FLOWS</span>
              <Activity className="w-3.5 h-3.5 text-blue-400" />
            </div>
            <div className="text-xl font-bold font-mono text-slate-100 mt-2">
              {traffic.filter((t) => t.state === 'allowed' || t.state === 'pending').length}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">Live kernel sockets</div>
          </div>

          {/* Card 2: Total Allowed */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>ALLOWED</span>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-2">
              {stats.allowedCount}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">Permitted flows</div>
          </div>

          {/* Card 3: Total Blocked */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>BLOCKED</span>
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            </div>
            <div className="text-xl font-bold font-mono text-red-400 mt-2">
              {stats.blockedCount}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">Dropped via rules</div>
          </div>

          {/* Card 4: Prompts Prompted */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>UI ALERTS</span>
              <Zap className="w-3.5 h-3.5 text-amber-400" />
            </div>
            <div className="text-xl font-bold font-mono text-amber-400 mt-2">
              {stats.promptCount}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">User decisions</div>
          </div>

          {/* Card 5: Rules Count */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>TOTAL RULES</span>
              <Shield className="w-3.5 h-3.5 text-purple-400" />
            </div>
            <div className="text-xl font-bold font-mono text-purple-400 mt-2">
              {rules.length}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">Permanent & session</div>
          </div>

          {/* Card 6: Inspected Volume */}
          <div className="bg-[#141416] border border-[#27272a] rounded-xl p-3.5 flex flex-col justify-between shadow-sm">
            <div className="flex items-center justify-between text-gray-500 text-[11px] font-mono">
              <span>INSPECTED</span>
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="text-xl font-bold font-mono text-slate-100 mt-2 truncate">
              {formatBytes(stats.bytesTotal)}
            </div>
            <div className="text-[10px] text-gray-500 mt-1">Payload inspected</div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {activeTab === 'traffic' && (
          <TrafficMonitor
            traffic={traffic}
            onClear={() => {
              daemon.clearTraffic();
              showToast('Traffic log cleared.', 'info');
            }}
            onBlockProcess={handleBlockProcess}
            onAllowProcess={handleAllowProcess}
          />
        )}

        {activeTab === 'rules' && (
          <RuleManager
            rules={rules}
            onAddRule={handleAddRule}
            onDeleteRule={handleDeleteRule}
          />
        )}

        {activeTab === 'simulator' && (
          <TrafficSimulator onSimulate={handleSimulate} />
        )}

        {activeTab === 'ipc' && (
          <IpcInspector ipcLogs={daemon.getIpcLogs()} />
        )}

        {activeTab === 'drivers' && (
          <KernelDrivers />
        )}

        {activeTab === 'source' && (
          <SourceCodeTree />
        )}
      </main>

      {/* Interactive Alert Modal (Triggered by Daemon or Simulation) */}
      <AlertModal
        alert={pendingAlert}
        onDecision={handleDecision}
        onDismiss={() => daemon.dismissAlert()}
      />

      {/* Changelog Modal */}
      <ChangelogModal
        isOpen={isChangelogOpen}
        onClose={() => setIsChangelogOpen(false)}
        version={stats.daemonVersion}
      />

      {/* Real Live Daemon Setup & Status Modal */}
      <LiveDaemonModal
        isOpen={isLiveModalOpen}
        onClose={() => setIsLiveModalOpen(false)}
        connectionState={connectionState}
        onConnect={(url) => {
          daemon.connectToLiveDaemon(url, true);
          showToast(`Attempting connection to live daemon at ${url}...`, 'info');
        }}
        onDisconnect={() => {
          daemon.disconnectLiveDaemon();
          showToast('Disconnected from live daemon. Operating in simulation mode.', 'info');
        }}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-16 right-6 z-50 animate-in fade-in slide-in-from-bottom-2 duration-150">
          <div
            className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl border shadow-xl text-xs font-medium ${
              toastMessage.type === 'success'
                ? 'bg-[#141416] border-emerald-500/40 text-emerald-400'
                : toastMessage.type === 'error'
                ? 'bg-[#141416] border-red-500/40 text-red-400'
                : 'bg-[#141416] border-blue-500/40 text-blue-400'
            }`}
          >
            {toastMessage.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            {toastMessage.type === 'error' && <ShieldAlert className="w-4 h-4 text-red-400" />}
            {toastMessage.type === 'info' && <Info className="w-4 h-4 text-blue-400" />}
            <span className="text-slate-200">{toastMessage.text}</span>
            <button
              onClick={() => setToastMessage(null)}
              className="text-gray-500 hover:text-slate-200 ml-1 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Bottom Status Footer */}
      <Footer stats={stats} onOpenChangelog={() => setIsChangelogOpen(true)} />
    </div>
  );
}
