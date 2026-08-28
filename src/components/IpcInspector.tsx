/**
 * SnitchGuard - WebSocket IPC Protocol Inspector (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { Terminal, ArrowUpRight, ArrowDownLeft, Copy, Check, Filter } from 'lucide-react';
import { IpcPacket } from '../types/firewall';

interface IpcInspectorProps {
  logs: IpcPacket[];
}

export const IpcInspector: React.FC<IpcInspectorProps> = ({ logs }) => {
  const [selectedLog, setSelectedLog] = useState<IpcPacket | null>(logs[0] || null);
  const [copied, setCopied] = useState(false);
  const [filterType, setFilterType] = useState<string>('all');

  const filtered = logs.filter((l) => filterType === 'all' || l.type === filterType);

  const handleCopy = (json: string) => {
    navigator.clipboard.writeText(json);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Overview Banner */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-purple-400" />
            <h2 className="text-xs font-bold text-gray-400 uppercase tracking-widest">Internal WebSocket IPC Wire Protocol</h2>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            Real-time JSON messages exchanged over <code className="text-blue-400 font-mono">ws://127.0.0.1:9095/ws</code> between Go daemon and Neutralino client.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[#1c1c1f] border border-[#27272a] text-gray-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
          >
            <option value="all">All Message Types</option>
            <option value="ALERT_PROMPT">ALERT_PROMPT (Daemon &rarr; UI)</option>
            <option value="DECISION">DECISION (UI &rarr; Daemon)</option>
            <option value="TRAFFIC_EVENT">TRAFFIC_EVENT (Live Stream)</option>
            <option value="RULE_LIST">RULE_LIST (Rule Sync)</option>
            <option value="ADD_RULE">ADD_RULE</option>
            <option value="DELETE_RULE">DELETE_RULE</option>
          </select>
        </div>
      </div>

      {/* Split Pane: Log List & JSON Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Event Stream */}
        <div className="lg:col-span-5 bg-[#141416] border border-[#27272a] rounded-2xl overflow-hidden flex flex-col max-h-[560px] shadow-xl">
          <div className="px-4 py-3 bg-[#1c1c1f] border-b border-[#27272a] text-[11px] font-bold text-gray-500 uppercase tracking-wider flex items-center justify-between">
            <span>PACKET STREAM</span>
            <span className="font-mono text-gray-400">{filtered.length} MESSAGES</span>
          </div>

          <div className="overflow-y-auto divide-y divide-[#27272a] flex-1">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500">No IPC messages captured yet.</div>
            ) : (
              filtered.map((log) => {
                const isToUi = log.direction === 'daemon_to_ui';
                const isSelected = selectedLog?.id === log.id;

                return (
                  <div
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className={`p-3 text-xs cursor-pointer transition flex items-start gap-2.5 ${
                      isSelected ? 'bg-white/[0.04] border-l-2 border-blue-500' : 'hover:bg-white/[0.02]'
                    }`}
                  >
                    <div className="pt-0.5">
                      {isToUi ? (
                        <span className="p-1 rounded bg-emerald-500/10 text-emerald-400 inline-block" title="Daemon to UI">
                          <ArrowDownLeft className="w-3.5 h-3.5" />
                        </span>
                      ) : (
                        <span className="p-1 rounded bg-blue-500/10 text-blue-400 inline-block" title="UI to Daemon">
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </span>
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="font-mono font-bold text-slate-200 text-[11px]">{log.type}</span>
                        <span className="font-mono text-[10px] text-gray-500">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-[11px] text-gray-400 truncate font-mono">
                        {JSON.stringify(log.payload)}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Detailed JSON Payload Inspector */}
        <div className="lg:col-span-7 bg-[#141416] border border-[#27272a] rounded-2xl overflow-hidden flex flex-col max-h-[560px] shadow-xl">
          <div className="px-4 py-3 bg-[#1c1c1f] border-b border-[#27272a] flex items-center justify-between text-xs">
            <span className="font-mono text-[11px] font-bold text-gray-400 uppercase tracking-wider">
              PAYLOAD INSPECTOR &bull; {selectedLog ? selectedLog.type : 'NONE SELECTED'}
            </span>
            {selectedLog && (
              <button
                onClick={() => handleCopy(JSON.stringify(selectedLog.payload, null, 2))}
                className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 font-mono transition cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
              </button>
            )}
          </div>

          <div className="p-4 overflow-y-auto flex-1 bg-[#0a0a0b] font-mono text-xs text-slate-200">
            {selectedLog ? (
              <pre className="whitespace-pre-wrap leading-relaxed text-blue-300">
                {JSON.stringify(
                  {
                    type: selectedLog.type,
                    direction: selectedLog.direction === 'daemon_to_ui' ? 'DAEMON -> UI' : 'UI -> DAEMON',
                    timestamp: selectedLog.timestamp,
                    payload: selectedLog.payload
                  },
                  null,
                  2
                )}
              </pre>
            ) : (
              <div className="text-gray-500 text-center py-20">Select an IPC packet from the stream to inspect.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

