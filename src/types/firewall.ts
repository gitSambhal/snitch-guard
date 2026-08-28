/**
 * SnitchGuard - Type Definitions
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

export type FirewallAction = 'allow' | 'block';
export type RuleDuration = 'once' | 'session' | 'always';
export type ProtocolType = 'tls' | 'http' | 'tcp' | 'udp';
export type ConnectionState = 'pending' | 'allowed' | 'blocked' | 'closed';

export interface ProcessMetadata {
  pid: number;
  name: string;
  path: string;
  commandLine?: string;
  user?: string;
  signature?: string;
  icon?: string;
}

export interface ConnectionEvent {
  id: string;
  timestamp: string;
  process: ProcessMetadata;
  processName: string;
  processPath: string;
  pid: number;
  localAddr: string;
  remoteIP: string;
  remotePort: number;
  domain: string;
  protocol: ProtocolType;
  bytesSent: number;
  bytesRecv: number;
  state: ConnectionState;
}

export interface FirewallRule {
  id: string;
  processPath: string;
  processName: string;
  domainPattern: string;
  remoteIP: string;
  remotePort: number;
  protocol: string;
  action: FirewallAction;
  duration: RuleDuration;
  createdAt: string;
  hitCount: number;
  lastHit?: string;
  comment?: string;
}

export interface DaemonMetrics {
  activeFlows: number;
  totalRules: number;
  blockedCount: number;
  allowedCount: number;
  promptCount: number;
  bytesTotal: number;
  uptimeSeconds: number;
  daemonVersion: string;
  platformDriver: string;
  connectedClients: number;
  isLiveDaemonConnected?: boolean;
  daemonUrl?: string;
}

export interface DaemonConnectionState {
  status: 'connected' | 'connecting' | 'disconnected' | 'simulation';
  daemonUrl: string;
  latencyMs?: number;
  lastPing?: string;
  error?: string;
}

export interface IpcPacket {
  id: string;
  timestamp: string;
  direction: 'daemon_to_ui' | 'ui_to_daemon';
  type: string;
  payload: any;
}
