/**
 * SnitchGuard - Packet Injector & Outbound Traffic Simulator (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React, { useState } from 'react';
import { PlayCircle, Terminal, Send, ShieldAlert, Sparkles, RefreshCw, Zap } from 'lucide-react';
import { ProtocolType } from '../types/firewall';

interface TrafficSimulatorProps {
  onSimulate: (opts: {
    processName: string;
    processPath?: string;
    domain: string;
    remoteIP: string;
    port: number;
    protocol: ProtocolType;
  }) => void;
}

export const TrafficSimulator: React.FC<TrafficSimulatorProps> = ({ onSimulate }) => {
  const [customProc, setCustomProc] = useState('curl');
  const [customPath, setCustomPath] = useState('/usr/bin/curl');
  const [customDomain, setCustomDomain] = useState('telemetry.dropbox.com');
  const [customIP, setCustomIP] = useState('162.125.6.20');
  const [customPort, setCustomPort] = useState(443);
  const [customProto, setCustomProto] = useState<ProtocolType>('tls');

  const presets = [
    {
      title: 'cURL -> api.github.com',
      proc: 'curl',
      path: '/usr/bin/curl',
      domain: 'api.github.com',
      ip: '140.82.121.4',
      port: 443,
      proto: 'tls' as const,
      desc: 'Developer API HTTPS stream'
    },
    {
      title: 'Spotify -> audio-fa.spotify.com',
      proc: 'spotify',
      path: '/usr/bin/spotify',
      domain: 'audio-fa.spotify.com',
      ip: '35.186.224.25',
      port: 443,
      proto: 'tls' as const,
      desc: 'High-bandwidth audio CDN'
    },
    {
      title: 'VS Code -> telemetry.visualstudio.com',
      proc: 'code',
      path: '/usr/share/code/code',
      domain: 'telemetry.visualstudio.com',
      ip: '20.54.89.10',
      port: 443,
      proto: 'tls' as const,
      desc: 'IDE background diagnostics'
    },
    {
      title: 'Python -> c2-beacon.darknet.io',
      proc: 'python3',
      path: '/usr/bin/python3',
      domain: 'c2-beacon.darknet.io',
      ip: '198.51.100.77',
      port: 8443,
      proto: 'tcp' as const,
      desc: 'Suspicious script socket beacon'
    },
    {
      title: 'Docker -> registry-1.docker.io',
      proc: 'dockerd',
      path: '/usr/bin/dockerd',
      domain: 'registry-1.docker.io',
      ip: '54.236.113.205',
      port: 443,
      proto: 'tls' as const,
      desc: 'Container image registry pull'
    },
    {
      title: 'Dropbox -> telemetry.dropbox.com',
      proc: 'Dropbox',
      path: '/Applications/Dropbox.app/Contents/MacOS/Dropbox',
      domain: 'telemetry.dropbox.com',
      ip: '162.125.6.20',
      port: 443,
      proto: 'tls' as const,
      desc: 'Desktop client telemetry sync'
    }
  ];

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSimulate({
      processName: customProc,
      processPath: customPath,
      domain: customDomain,
      remoteIP: customIP,
      port: customPort,
      protocol: customProto
    });
  };

  return (
    <div className="space-y-6">
      {/* Preset Cards */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-5 shadow-xl">
        <div className="flex items-center gap-2 mb-2 text-blue-400 font-semibold text-xs uppercase tracking-wider">
          <Sparkles className="w-4 h-4" />
          <span>Quick Scenario Injection Presets</span>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Click any preset to simulate an outbound TCP/TLS socket flow through the elevated Go daemon:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {presets.map((p, idx) => (
            <div
              key={idx}
              className="bg-[#1c1c1f] border border-[#27272a] hover:border-gray-700 rounded-xl p-4 transition hover:shadow-lg flex flex-col justify-between group"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-xs font-bold text-slate-200">{p.proc}</span>
                  <span className="bg-[#141416] text-gray-400 font-mono text-[10px] px-1.5 py-0.5 rounded uppercase border border-[#27272a]">
                    {p.proto}
                  </span>
                </div>
                <div className="text-xs text-blue-400 font-mono font-medium truncate mb-1">{p.domain}</div>
                <div className="text-[11px] text-gray-500">{p.desc}</div>
              </div>

              <button
                onClick={() =>
                  onSimulate({
                    processName: p.proc,
                    processPath: p.path,
                    domain: p.domain,
                    remoteIP: p.ip,
                    port: p.port,
                    protocol: p.proto
                  })
                }
                className="mt-3 w-full flex items-center justify-center gap-1.5 bg-[#141416] hover:bg-blue-600 hover:text-white text-gray-300 border border-[#27272a] hover:border-blue-500 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer"
              >
                <PlayCircle className="w-3.5 h-3.5" />
                <span>Inject Connection</span>
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Custom Packet Forge */}
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-2 text-slate-100 font-bold text-sm uppercase tracking-wider">
          <Terminal className="w-4 h-4 text-blue-400" />
          <span>Custom Packet Forge & Process Emulator</span>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Customize individual socket attributes to evaluate exact rule edge cases and verify SNI extraction.
        </p>

        <form onSubmit={handleCustomSubmit} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-gray-400 mb-1 font-mono">PROCESS BINARY NAME</label>
              <input
                type="text"
                value={customProc}
                onChange={(e) => setCustomProc(e.target.value)}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-mono">ABSOLUTE BINARY PATH</label>
              <input
                type="text"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-mono">TARGET SNI DOMAIN</label>
              <input
                type="text"
                value={customDomain}
                onChange={(e) => setCustomDomain(e.target.value)}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-blue-400 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-mono">REMOTE DESTINATION IP</label>
              <input
                type="text"
                value={customIP}
                onChange={(e) => setCustomIP(e.target.value)}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-mono">PORT</label>
              <input
                type="number"
                value={customPort}
                onChange={(e) => setCustomPort(Number(e.target.value))}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-gray-400 mb-1 font-mono">PROTOCOL</label>
              <select
                value={customProto}
                onChange={(e) => setCustomProto(e.target.value as ProtocolType)}
                className="w-full bg-[#1c1c1f] border border-[#27272a] rounded-lg px-3 py-2 text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              >
                <option value="tls">TLS (ClientHello SNI RFC 6066)</option>
                <option value="http">HTTP (Host Header)</option>
                <option value="tcp">Raw TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-bold px-5 py-2.5 rounded-xl shadow-lg shadow-blue-900/30 transition cursor-pointer"
            >
              <Send className="w-4 h-4" />
              <span>Dispatch Packet to Interceptor</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

