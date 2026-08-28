/**
 * SnitchGuard - Application Footer (Elegant Dark Theme)
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import React from 'react';
import { ExternalLink, ShieldCheck, Activity, Terminal, Lock } from 'lucide-react';
import { DaemonMetrics } from '../types/firewall';

interface FooterProps {
  stats: DaemonMetrics;
  onOpenChangelog: () => void;
}

export const Footer: React.FC<FooterProps> = ({ stats, onOpenChangelog }) => {
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const formatUptime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  return (
    <footer className="h-12 border-t border-[#27272a] px-6 flex items-center justify-between bg-[#0a0a0b] text-xs text-gray-500 font-mono mt-auto select-none">
      {/* Left Daemon Wire Status */}
      <div className="flex items-center gap-4 text-[11px]">
        <span className="flex items-center gap-1.5 text-gray-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
          <span>WS: 127.0.0.1:9095 (CONNECTED)</span>
        </span>
        <span className="text-gray-700 hidden sm:inline">|</span>
        <span className="hidden sm:inline text-gray-500">
          ENCLAVE: ACTIVE (eBPF / NetExt)
        </span>
        <span className="text-gray-700 hidden md:inline">|</span>
        <span className="hidden md:inline text-gray-500">
          INSPECTED: <span className="text-slate-300">{formatBytes(stats.bytesTotal)}</span>
        </span>
      </div>

      {/* Center / Right Attribution & Version */}
      <div className="flex items-center gap-3">
        <div className="text-[11px] text-gray-400">
          Created by{' '}
          <a
            href="https://suhail.top"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1 transition"
          >
            Suhail Akhtar
            <ExternalLink className="w-2.5 h-2.5" />
          </a>
        </div>
        <span className="text-gray-700">|</span>
        <button
          onClick={onOpenChangelog}
          className="bg-[#1c1c1f] hover:bg-[#27272a] border border-[#27272a] text-gray-300 px-2 py-0.5 rounded text-[10px] font-mono transition cursor-pointer"
        >
          {stats.daemonVersion}
        </button>
      </div>
    </footer>
  );
};

