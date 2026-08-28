/**
 * SnitchGuard - What's New & Changelog Modal
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React from 'react';
import { X, Sparkles, Shield, Terminal, Cpu, CheckCircle2, ExternalLink } from 'lucide-react';

interface ChangelogModalProps {
  isOpen: boolean;
  onClose: () => void;
  version: string;
}

export const ChangelogModal: React.FC<ChangelogModalProps> = ({ isOpen, onClose, version }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0a0b]/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-[#141416] border border-[#27272a] rounded-2xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Modal Header */}
        <div className="p-6 border-b border-[#27272a] flex items-center justify-between bg-[#1c1c1f]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-100">Release Notes & Changelog</h3>
                <span className="bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px] font-mono px-2 py-0.5 rounded-full font-bold">
                  {version}
                </span>
              </div>
              <p className="text-xs text-gray-500">Cross-Platform Host Application Firewall</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-slate-200 hover:bg-[#27272a] rounded-lg transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-gray-300">
          <div className="bg-[#1c1c1f] border border-[#27272a] rounded-xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <p className="font-semibold text-slate-100">SnitchGuard Production Daemon v1.0.0</p>
                <p className="text-gray-500 text-[11px]">eBPF (Linux) &bull; NetworkExtension (macOS) &bull; WFP (Windows)</p>
              </div>
            </div>
            <a
              href="https://suhail.top"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1 font-mono text-[11px]"
            >
              Author: Suhail Akhtar
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          {/* Section: Added Features */}
          <div>
            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Release History</span>
            </h4>

            <div className="space-y-3 font-mono">
              <div className="bg-[#0a0a0b] p-3 rounded-lg border border-blue-500/30">
                <div className="flex items-center justify-between mb-1">
                  <p className="font-bold text-blue-400 text-[11px]">v1.1.0 &bull; AUTOMATED MULTI-PLATFORM GITHUB ACTIONS RELEASE</p>
                  <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">NEW</span>
                </div>
                <ul className="list-disc list-inside space-y-1 text-gray-400 text-[11px]">
                  <li>CI/CD GitHub Action (<code className="text-slate-200">.github/workflows/release.yml</code>) triggered on push/merge to <code className="text-slate-200">main</code> and <code className="text-slate-200">v*</code> tags.</li>
                  <li>Multi-platform Go daemon cross-compilation matrix (<code className="text-slate-200">linux/amd64</code>, <code className="text-slate-200">linux/arm64</code>, <code className="text-slate-200">darwin/amd64</code>, <code className="text-slate-200">darwin/arm64</code>, <code className="text-slate-200">windows/amd64</code>).</li>
                  <li>Automated Neutralinojs desktop packaging into self-contained release archives (<code className="text-slate-200">.tar.gz</code> & <code className="text-slate-200">.zip</code>).</li>
                  <li>Automatic GitHub Releases publishing with SHA-256 checksums (<code className="text-slate-200">SHA256SUMS.txt</code>) and release notes.</li>
                </ul>
              </div>

              <div className="bg-[#0a0a0b] p-3 rounded-lg border border-[#27272a]">
                <p className="font-bold text-blue-400 text-[11px] mb-1">v1.0.0 &bull; ELEVATED GO DAEMON ENGINE (`daemon/`)</p>
                <ul className="list-disc list-inside space-y-1 text-gray-400 text-[11px]">
                  <li>Stateful Rule Engine with domain wildcard matching (<code className="text-slate-200">*.domain.com</code>) & JSON persistence.</li>
                  <li>RFC 6066 TLS ClientHello SNI Extractor reading destination hostnames from initial TCP payloads.</li>
                  <li>Cross-platform socket-to-process resolver (<code className="text-slate-200">/proc/net/tcp</code>, <code className="text-slate-200">libproc</code>, Windows IP Helper).</li>
                  <li>Internal WebSocket IPC server at <code className="text-blue-300">ws://127.0.0.1:9095/ws</code> for sub-millisecond client synchronization.</li>
                </ul>
              </div>

              <div className="bg-[#0a0a0b] p-3 rounded-lg border border-[#27272a]">
                <p className="font-bold text-purple-400 text-[11px] mb-1">NEUTRALINOJS DESKTOP CLIENT (`ui/`)</p>
                <ul className="list-disc list-inside space-y-1 text-gray-400 text-[11px]">
                  <li>Interactive 30s connection alert popup with 4-way decision matrix (Allow/Deny x Once/Always).</li>
                  <li>Real-time socket flows inspector with process badges, bandwidth meters, and kill/block switches.</li>
                  <li>Subdomain wildcard rule synthesizer with instant regex tester.</li>
                  <li>Packet forge simulator for injecting mock flows from binaries like <code className="text-slate-200">curl</code>, <code className="text-slate-200">spotify</code>, and <code className="text-slate-200">code</code>.</li>
                </ul>
              </div>

              <div className="bg-[#0a0a0b] p-3 rounded-lg border border-[#27272a]">
                <p className="font-bold text-emerald-400 text-[11px] mb-1">KERNEL DRIVER BLUEPRINTS & BUILD SCRIPTS</p>
                <ul className="list-disc list-inside space-y-1 text-gray-400 text-[11px]">
                  <li>Linux eBPF TC egress filter blueprints and socket hook architecture.</li>
                  <li>Complete <code className="text-slate-200">Makefile</code> and <code className="text-slate-200">neutralino.config.json</code> build recipes.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#27272a] bg-[#1c1c1f] flex items-center justify-between">
          <span className="text-[11px] text-gray-500">
            Created with craft by <a href="https://suhail.top" target="_blank" rel="noopener noreferrer" className="text-blue-400 underline">Suhail Akhtar</a>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
