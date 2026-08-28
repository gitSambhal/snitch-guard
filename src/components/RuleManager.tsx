/**
 * SnitchGuard - Stateful Rule Engine & Firewall Rule Manager (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { ListFilter, Plus, Trash2, ShieldCheck, ShieldAlert, Search, Download, Check, X, Sparkles } from 'lucide-react';
import { FirewallRule, FirewallAction, RuleDuration } from '../types/firewall';

interface RuleManagerProps {
  rules: FirewallRule[];
  onAddRule: (rule: Partial<FirewallRule>) => void;
  onDeleteRule: (id: string) => void;
}

export const RuleManager: React.FC<RuleManagerProps> = ({ rules, onAddRule, onDeleteRule }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [isAdding, setIsAdding] = useState(false);

  // Wildcard Test Tool State
  const [testPattern, setTestPattern] = useState('*.github.com');
  const [testDomain, setTestDomain] = useState('api.github.com');

  // New Rule Form State
  const [newProcess, setNewProcess] = useState('curl');
  const [newDomain, setNewDomain] = useState('*.dropbox.com');
  const [newIP, setNewIP] = useState('*');
  const [newPort, setNewPort] = useState(443);
  const [newProto, setNewProto] = useState('tls');
  const [newAction, setNewAction] = useState<FirewallAction>('allow');
  const [newDuration, setNewDuration] = useState<RuleDuration>('always');
  const [newComment, setNewComment] = useState('');

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      !searchTerm ||
      r.processName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.domainPattern.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.comment && r.comment.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesAction = actionFilter === 'all' || r.action === actionFilter;

    return matchesSearch && matchesAction;
  });

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    onAddRule({
      processName: newProcess || '*',
      processPath: newProcess === '*' ? '*' : `/usr/bin/${newProcess}`,
      domainPattern: newDomain || '*',
      remoteIP: newIP || '*',
      remotePort: Number(newPort) || 0,
      protocol: newProto || '*',
      action: newAction,
      duration: newDuration,
      comment: newComment || `Rule for ${newProcess} -> ${newDomain}`
    });
    setIsAdding(false);
    setNewComment('');
  };

  const testWildcardMatch = (pattern: string, domain: string) => {
    pattern = pattern.trim().toLowerCase();
    domain = domain.trim().toLowerCase();
    if (pattern === '*' || pattern === domain) return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.substring(1);
      if (domain.endsWith(suffix) || domain === pattern.substring(2)) return true;
    }
    if (pattern.endsWith('.*')) {
      const prefix = pattern.substring(0, pattern.length - 2);
      if (domain.startsWith(prefix)) return true;
    }
    return false;
  };

  const isMatched = testWildcardMatch(testPattern, testDomain);

  const exportRulesJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rules, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', 'firewall_rules.json');
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Wildcard Sandbox */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-1.5 text-blue-400 text-xs font-semibold uppercase tracking-wider">
          <Sparkles className="w-4 h-4" />
          <span>Domain Wildcard Expression Sandbox</span>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Test how the elevated Go daemon resolves SNI domain wildcard patterns (e.g. <code>*.github.com</code> or <code>*.telemetry.*</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
          <div>
            <label className="block text-[11px] text-gray-400 mb-1 font-mono uppercase">RULE PATTERN</label>
            <input
              type="text"
              value={testPattern}
              onChange={(e) => setTestPattern(e.target.value)}
              className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-1.5 text-xs text-blue-400 font-mono focus:border-blue-500 focus:outline-none"
              placeholder="e.g. *.github.com"
            />
          </div>

          <div>
            <label className="block text-[11px] text-gray-400 mb-1 font-mono uppercase">TEST TARGET DOMAIN</label>
            <input
              type="text"
              value={testDomain}
              onChange={(e) => setTestDomain(e.target.value)}
              className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-1.5 text-xs text-emerald-400 font-mono focus:border-blue-500 focus:outline-none"
              placeholder="e.g. api.github.com"
            />
          </div>

          <div className="md:pt-4">
            <div
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono font-semibold border ${
                isMatched
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : 'bg-red-500/10 text-red-400 border-red-500/20'
              }`}
            >
              {isMatched ? <Check className="w-4 h-4" /> : <X className="w-4 h-4" />}
              <span>{isMatched ? 'MATCHED (Rule Applied)' : 'NO MATCH (Unruled)'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Table Toolbar */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search rules by process, domain wildcard, or comment..."
              className="w-full bg-[#1c1c1f] border border-[#27272a] focus:border-blue-500 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none transition"
            />
          </div>

          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-[#1c1c1f] border border-[#27272a] text-gray-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
          >
            <option value="all">All Actions</option>
            <option value="allow">Allow Only</option>
            <option value="block">Block Only</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportRulesJson}
            className="flex items-center gap-1.5 bg-[#1c1c1f] hover:bg-[#27272a] text-gray-300 border border-[#27272a] px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={() => setIsAdding(true)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-1.5 rounded-lg text-xs font-bold shadow-lg shadow-blue-900/30 transition cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Rule</span>
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl overflow-hidden shadow-xl">
        <div className="px-5 py-3 border-b border-[#27272a] flex items-center justify-between bg-[#1c1c1f]">
          <div className="flex items-center gap-2">
            <ListFilter className="w-4 h-4 text-blue-400" />
            <h2 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Stateful Firewall Rules (`firewall_rules.json`)</h2>
          </div>
          <span className="text-xs text-gray-500 font-mono">{filteredRules.length} Rules Active</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#1c1c1f] text-gray-500 font-mono text-[11px] border-b border-[#27272a]">
                <th className="py-3 px-4 font-bold uppercase">ACTION</th>
                <th className="py-3 px-4 font-bold uppercase">PROCESS PATH</th>
                <th className="py-3 px-4 font-bold uppercase">DOMAIN WILDCARD</th>
                <th className="py-3 px-4 font-bold uppercase">REMOTE IP:PORT</th>
                <th className="py-3 px-4 font-bold uppercase">DURATION</th>
                <th className="py-3 px-4 font-bold uppercase">HITS</th>
                <th className="py-3 px-4 font-bold uppercase">NOTES</th>
                <th className="py-3 px-4 font-bold uppercase text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#27272a]">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-10 text-gray-500">
                    No rules found. Add one above or capture from live traffic.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => {
                  const isAllow = rule.action === 'allow';
                  return (
                    <tr key={rule.id} className="hover:bg-white/[0.02] transition">
                      <td className="py-3 px-4">
                        {isAllow ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase">
                            <ShieldCheck className="w-3 h-3" /> ALLOW
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20 uppercase">
                            <ShieldAlert className="w-3 h-3" /> BLOCK
                          </span>
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono">
                        <div className="font-semibold text-slate-200">{rule.processName}</div>
                        <div className="text-[10px] text-gray-500 truncate max-w-[160px]">{rule.processPath}</div>
                      </td>

                      <td className="py-3 px-4 font-mono font-medium text-blue-400">
                        {rule.domainPattern}
                      </td>

                      <td className="py-3 px-4 font-mono text-gray-300">
                        {rule.remoteIP}:{rule.remotePort === 0 ? '*' : rule.remotePort}
                      </td>

                      <td className="py-3 px-4 text-gray-400 capitalize text-[11px]">
                        {rule.duration}
                      </td>

                      <td className="py-3 px-4 font-mono text-slate-300 font-semibold">
                        {rule.hitCount}
                      </td>

                      <td className="py-3 px-4 text-gray-400 text-[11px] truncate max-w-[180px]">
                        {rule.comment || '-'}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => onDeleteRule(rule.id)}
                          className="text-gray-500 hover:text-red-400 p-1 rounded hover:bg-[#1c1c1f] transition cursor-pointer"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Rule Modal */}
      {isAdding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0a0b]/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-[#1e1e21] border border-[#27272a] rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#27272a] pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Add Firewall Filtering Rule</h3>
              <button onClick={() => setIsAdding(false)} className="text-gray-400 hover:text-slate-200 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-400 mb-1 font-mono">Process Name / Path (* for any)</label>
                <input
                  type="text"
                  value={newProcess}
                  onChange={(e) => setNewProcess(e.target.value)}
                  className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. curl or /usr/bin/curl"
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1 font-mono">Domain Wildcard Pattern (* for any)</label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-blue-400 font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. *.github.com or api.stripe.com"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-400 mb-1 font-mono">Remote IP (* for any)</label>
                  <input
                    type="text"
                    value={newIP}
                    onChange={(e) => setNewIP(e.target.value)}
                    className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 mb-1 font-mono">Port (0 for any)</label>
                  <input
                    type="number"
                    value={newPort}
                    onChange={(e) => setNewPort(Number(e.target.value))}
                    className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-gray-400 mb-1 font-mono">Verdict Action</label>
                  <select
                    value={newAction}
                    onChange={(e) => setNewAction(e.target.value as FirewallAction)}
                    className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 focus:outline-none"
                  >
                    <option value="allow">ALLOW</option>
                    <option value="block">BLOCK</option>
                  </select>
                </div>
                <div>
                  <label className="block text-gray-400 mb-1 font-mono">Duration Persistence</label>
                  <select
                    value={newDuration}
                    onChange={(e) => setNewDuration(e.target.value as RuleDuration)}
                    className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 focus:outline-none"
                  >
                    <option value="always">Always (Persist to JSON)</option>
                    <option value="session">Session (Memory Only)</option>
                    <option value="once">Once (Single Match)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-gray-400 mb-1 font-mono">Comment / Description</label>
                <input
                  type="text"
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  className="w-full bg-[#141416] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. Developer API Allowlist"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setIsAdding(false)}
                  className="px-4 py-2 rounded-lg bg-[#27272a] text-gray-300 hover:bg-[#38383d] transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold shadow-lg shadow-blue-900/30 transition cursor-pointer"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

