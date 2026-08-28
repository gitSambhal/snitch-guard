/**
 * SnitchGuard - Neutralinojs Native Runtime Bridge & Auto-Daemon Spawner
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

import { daemon } from './mockDaemon';

declare global {
  interface Window {
    Neutralino?: any;
    NL_PORT?: number;
    NL_TOKEN?: string;
    NL_ARGS?: string[];
    NL_PATH?: string;
    NL_APPID?: string;
  }
}

export interface NativeRuntimeStatus {
  isNeutralino: boolean;
  daemonProcessId?: number;
  isDaemonAutoSpawned: boolean;
  osName?: string;
  appVersion?: string;
  nativeDirectory?: string;
  errorMessage?: string;
}

class NeutralinoBridgeService {
  private status: NativeRuntimeStatus = {
    isNeutralino: false,
    isDaemonAutoSpawned: false
  };

  private listeners: Array<(status: NativeRuntimeStatus) => void> = [];

  constructor() {
    this.init();
  }

  public subscribe(cb: (status: NativeRuntimeStatus) => void): () => void {
    this.listeners.push(cb);
    cb(this.status);
    return () => {
      this.listeners = this.listeners.filter(l => l !== cb);
    };
  }

  private notify() {
    this.listeners.forEach(cb => cb(this.status));
  }

  public async init() {
    // Check if running inside Neutralino native desktop container
    if (typeof window !== 'undefined' && (window.Neutralino || window.NL_PORT)) {
      try {
        if (window.Neutralino && typeof window.Neutralino.init === 'function') {
          window.Neutralino.init();
        }

        this.status.isNeutralino = true;

        // Fetch OS details
        if (window.Neutralino?.os?.getEnv) {
          try {
            const osInfo = await window.Neutralino.computer?.getOSInfo?.();
            this.status.osName = osInfo?.description || 'Desktop Host';
          } catch {
            this.status.osName = 'Native OS Host';
          }
        }

        // Set up window close listener to gracefully terminate daemon
        if (window.Neutralino?.events?.on) {
          window.Neutralino.events.on('windowClose', async () => {
            if (this.status.daemonProcessId && window.Neutralino?.os?.execCommand) {
              try {
                // Terminate spawned daemon if we spawned it
                await window.Neutralino.os.execCommand(`kill -9 ${this.status.daemonProcessId}`);
              } catch {
                // ignore
              }
            }
            window.Neutralino.app.exit();
          });
        }

        // Auto-spawn the elevated Go daemon if not already running
        await this.autoSpawnDaemon();

        // Connect WebSocket to Go daemon
        daemon.connectToLiveDaemon('ws://127.0.0.1:9095/ws', false);
      } catch (err: any) {
        console.warn('[NeutralinoBridge] Native init error:', err);
        this.status.errorMessage = err?.message || 'Native Bridge Init Error';
      }
    } else {
      this.status.isNeutralino = false;
    }
    this.notify();
  }

  /**
   * Spawns the packaged Go daemon binary automatically
   */
  public async autoSpawnDaemon(): Promise<boolean> {
    if (!this.status.isNeutralino || !window.Neutralino?.os?.spawnProcess) {
      return false;
    }

    try {
      const daemonPath = window.NL_PATH
        ? `${window.NL_PATH}/bin/snitchguard-daemon`
        : './bin/snitchguard-daemon';

      console.log(`[NeutralinoBridge] Spawning native daemon at: ${daemonPath}`);

      const proc = await window.Neutralino.os.spawnProcess(
        `${daemonPath} --ws-port=9095 --proxy-port=9096 --rules=firewall_rules.json`
      );

      if (proc && proc.id) {
        this.status.daemonProcessId = proc.id;
        this.status.isDaemonAutoSpawned = true;
        this.notify();

        // Give the daemon 300ms to bind sockets, then connect
        setTimeout(() => {
          daemon.connectToLiveDaemon('ws://127.0.0.1:9095/ws', false);
        }, 500);

        return true;
      }
    } catch (err: any) {
      console.warn('[NeutralinoBridge] Could not auto-spawn daemon process directly:', err);
      // Fallback: the user or start script may have already launched the daemon
      daemon.connectToLiveDaemon('ws://127.0.0.1:9095/ws', false);
    }
    return false;
  }

  public getStatus(): NativeRuntimeStatus {
    return this.status;
  }
}

export const neutralinoBridge = new NeutralinoBridgeService();
