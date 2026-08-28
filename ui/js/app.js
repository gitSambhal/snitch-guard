/**
 * SnitchGuard - Neutralinojs Desktop Client Application Logic
 * Author: Suhail Akhtar (https://suhail.top)
 * License: MIT
 */

// Global State
let socket = null;
let currentAlert = null;
let rulesList = [];
let trafficHistory = [];
let reconnectTimer = null;

// Initialize Neutralino API (with graceful fallback if running in standard browser)
function initNeutralino() {
  if (typeof Neutralino !== 'undefined') {
    Neutralino.init();

    // Window controls
    document.getElementById('btn-minimize').addEventListener('click', () => {
      Neutralino.window.minimize();
    });

    document.getElementById('btn-maximize').addEventListener('click', async () => {
      if (await Neutralino.window.isMaximized()) {
        Neutralino.window.unmaximize();
      } else {
        Neutralino.window.maximize();
      }
    });

    document.getElementById('btn-close').addEventListener('click', () => {
      Neutralino.app.exit();
    });

    // Setup Tray Menu
    setupTray();
  } else {
    console.log('[Neutralino] Running in browser preview mode. Native OS hooks simulated.');
    document.getElementById('btn-minimize').style.display = 'none';
    document.getElementById('btn-maximize').style.display = 'none';
    document.getElementById('btn-close').style.display = 'none';
  }
}

async function setupTray() {
  if (typeof Neutralino === 'undefined' || !Neutralino.os) return;
  const tray = {
    icon: '/ui/icons/trayIcon.png',
    menuItems: [
      { id: 'SHOW', text: 'Open SnitchGuard Panel' },
      { id: 'SEP', text: '-' },
      { id: 'QUIT', text: 'Quit SnitchGuard' }
    ]
  };
  await Neutralino.os.setTray(tray);
  Neutralino.events.on('trayMenuItemClicked', (event) => {
    if (event.detail.id === 'SHOW') {
      Neutralino.window.show();
      Neutralino.window.focus();
    } else if (event.detail.id === 'QUIT') {
      Neutralino.app.exit();
    }
  });
}

// Connect to Elevated Go Daemon via WebSocket IPC
function connectToDaemon() {
  const wsUrl = 'ws://127.0.0.1:9095/ws';
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');

  console.log(`[IPC] Connecting to daemon at ${wsUrl}...`);
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    console.log('[IPC] Connected to Go daemon WebSocket server');
    statusDot.className = 'status-dot';
    statusText.textContent = 'Daemon Connected (127.0.0.1:9095)';
    if (reconnectTimer) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
    // Request current rule list
    socket.send(JSON.stringify({ type: 'GET_RULES' }));
  };

  socket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleDaemonMessage(msg);
    } catch (e) {
      console.error('[IPC] Malformed message received:', event.data, e);
    }
  };

  socket.onclose = () => {
    console.warn('[IPC] Disconnected from daemon. Retrying in 3s...');
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'Daemon Disconnected (Retrying...)';
    if (!reconnectTimer) {
      reconnectTimer = setInterval(connectToDaemon, 3000);
    }
  };

  socket.onerror = (err) => {
    console.error('[IPC] WebSocket error:', err);
  };
}

// Handle Incoming Daemon Messages
function handleDaemonMessage(msg) {
  switch (msg.type) {
    case 'ALERT_PROMPT':
      showAlertModal(msg.payload);
      break;

    case 'TRAFFIC_EVENT':
      recordTrafficEvent(msg.payload);
      break;

    case 'RULE_LIST':
      rulesList = msg.payload || [];
      renderRulesTable();
      break;

    case 'STATS_UPDATE':
      updateStatsUI(msg.payload);
      break;

    default:
      console.log('[IPC] Unhandled message:', msg);
  }
}

// Display Connection Alert Modal Pop-up
function showAlertModal(req) {
  currentAlert = req;
  const modal = document.getElementById('alert-modal');
  document.getElementById('alert-proc-name').textContent = req.process_name || 'unknown';
  document.getElementById('alert-proc-path').textContent = req.process_path || '/usr/bin/unknown';
  document.getElementById('alert-proc-pid').textContent = req.pid || '0';
  document.getElementById('alert-domain').textContent = req.domain || req.remote_ip;
  document.getElementById('alert-target').textContent = `${req.remote_ip}:${req.remote_port} (${req.protocol.toUpperCase()})`;
  document.getElementById('wildcard-preview').textContent = req.domain || 'example.com';

  modal.classList.add('show');

  // If Neutralino window was minimized or in background, focus it
  if (typeof Neutralino !== 'undefined' && Neutralino.window) {
    Neutralino.window.show();
    Neutralino.window.focus();
  }
}

function hideAlertModal() {
  const modal = document.getElementById('alert-modal');
  modal.classList.remove('show');
  currentAlert = null;
}

// Send Verdict Decision to Go Daemon
function sendDecision(action, duration) {
  if (!currentAlert || !socket || socket.readyState !== WebSocket.OPEN) return;

  const applyWildcard = document.getElementById('chk-wildcard').checked;
  const payload = {
    flow_id: currentAlert.id,
    action: action,               // "allow" or "block"
    duration: duration,           // "once", "session", "always"
    apply_wildcard: applyWildcard,
    domain: currentAlert.domain,
    process_path: currentAlert.process_path,
    process_name: currentAlert.process_name,
    remote_port: currentAlert.remote_port,
    protocol: currentAlert.protocol
  };

  socket.send(JSON.stringify({
    type: 'DECISION',
    payload: payload
  }));

  console.log('[IPC] Sent decision:', payload);
  hideAlertModal();
}

// Live Traffic Rendering
function recordTrafficEvent(req) {
  // Update or insert into history
  const idx = trafficHistory.findIndex(t => t.id === req.id);
  if (idx !== -1) {
    trafficHistory[idx] = req;
  } else {
    trafficHistory.unshift(req);
    if (trafficHistory.length > 100) trafficHistory.pop();
  }
  renderTrafficTable();
}

function renderTrafficTable() {
  const tbody = document.getElementById('traffic-table-body');
  if (!tbody) return;
  const filter = (document.getElementById('traffic-search')?.value || '').toLowerCase();

  const filtered = trafficHistory.filter(t => {
    return !filter ||
      (t.process_name && t.process_name.toLowerCase().includes(filter)) ||
      (t.domain && t.domain.toLowerCase().includes(filter)) ||
      (t.remote_ip && t.remote_ip.includes(filter));
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 24px;">No active traffic matching filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(t => {
    const timeStr = new Date(t.timestamp).toLocaleTimeString();
    let badgeClass = 'badge-pending';
    if (t.state === 'allowed') badgeClass = 'badge-allow';
    if (t.state === 'blocked') badgeClass = 'badge-block';

    const bytesSentKB = ((t.bytes_sent || 0) / 1024).toFixed(1);
    const bytesRecvKB = ((t.bytes_recv || 0) / 1024).toFixed(1);

    return `
      <tr>
        <td style="font-family: monospace; font-size: 11px; color: #94a3b8;">${timeStr}</td>
        <td>
          <div style="font-weight: 600; color: #38bdf8;">${escapeHtml(t.process_name)}</div>
          <div style="font-size: 10px; color: #64748b; font-family: monospace;">PID: ${t.pid}</div>
        </td>
        <td style="font-family: monospace; color: #34d399; font-weight: 500;">
          ${escapeHtml(t.domain || '-')}
        </td>
        <td style="font-family: monospace; font-size: 12px;">${escapeHtml(t.remote_ip)}:${t.remote_port}</td>
        <td style="text-transform: uppercase; font-size: 11px; font-weight: 600;">${t.protocol}</td>
        <td style="font-size: 11px; color: #94a3b8;">&uarr; ${bytesSentKB}KB / &darr; ${bytesRecvKB}KB</td>
        <td><span class="badge ${badgeClass}">${t.state}</span></td>
        <td>
          <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="blockProcessDirect('${escapeHtml(t.process_name)}')">Block Binary</button>
        </td>
      </tr>
    `;
  }).join('');
}

// Rules Table Rendering
function renderRulesTable() {
  const tbody = document.getElementById('rules-table-body');
  const countEl = document.getElementById('rule-count');
  if (countEl) countEl.textContent = rulesList.length;
  if (!tbody) return;

  const filter = (document.getElementById('rule-search')?.value || '').toLowerCase();

  const filtered = rulesList.filter(r => {
    return !filter ||
      (r.process_name && r.process_name.toLowerCase().includes(filter)) ||
      (r.domain_pattern && r.domain_pattern.toLowerCase().includes(filter));
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 24px;">No firewall rules configured.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    const badgeClass = r.action === 'allow' ? 'badge-allow' : 'badge-block';
    return `
      <tr>
        <td><span class="badge ${badgeClass}">${r.action}</span></td>
        <td>
          <div style="font-weight: 600;">${escapeHtml(r.process_name || 'Any (*)')}</div>
          <div style="font-size: 10px; color: #64748b; font-family: monospace;">${escapeHtml(r.process_path || '*')}</div>
        </td>
        <td style="font-family: monospace; color: #38bdf8;">${escapeHtml(r.domain_pattern || '*')}</td>
        <td style="font-family: monospace; font-size: 12px;">${escapeHtml(r.remote_ip || '*')}</td>
        <td style="font-family: monospace; font-size: 12px;">${r.remote_port === 0 ? 'Any' : r.remote_port}</td>
        <td style="text-transform: capitalize; font-size: 12px; color: #94a3b8;">${r.duration || 'always'}</td>
        <td style="font-family: monospace; font-size: 12px;">${r.hit_count || 0}</td>
        <td>
          <button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="deleteRule('${r.id}')">Delete</button>
        </td>
      </tr>
    `;
  }).join('');
}

function updateStatsUI(stats) {
  // Can be bound to toolbar badges if needed
}

function deleteRule(ruleId) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({
    type: 'DELETE_RULE',
    payload: { id: ruleId }
  }));
}

function blockProcessDirect(procName) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({
    type: 'ADD_RULE',
    payload: {
      process_name: procName,
      process_path: '*',
      domain_pattern: '*',
      remote_ip: '*',
      remote_port: 0,
      protocol: '*',
      action: 'block',
      duration: 'always',
      comment: `Manual block of ${procName}`
    }
  }));
}

// Trigger simulated traffic flow through the Go Daemon
function simulateTraffic(procName, domain, ip, port, protocol) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    alert('Go daemon is not connected. Make sure the daemon is running on :9095.');
    return;
  }

  socket.send(JSON.stringify({
    type: 'SIMULATE_TRAFFIC',
    payload: {
      process_name: procName,
      domain: domain,
      remote_ip: ip,
      port: port,
      protocol: protocol
    }
  }));
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Setup Event Listeners on Page Load
document.addEventListener('DOMContentLoaded', () => {
  initNeutralino();
  connectToDaemon();

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');

      btn.classList.add('active');
      const tabKey = btn.getAttribute('data-tab');
      const target = document.getElementById(`view-${tabKey}`);
      if (target) target.style.display = 'block';
    });
  });

  // Alert Decision Buttons
  document.getElementById('btn-allow-once')?.addEventListener('click', () => sendDecision('allow', 'once'));
  document.getElementById('btn-allow-always')?.addEventListener('click', () => sendDecision('allow', 'always'));
  document.getElementById('btn-deny-once')?.addEventListener('click', () => sendDecision('block', 'once'));
  document.getElementById('btn-deny-always')?.addEventListener('click', () => sendDecision('block', 'always'));

  // Clear Traffic
  document.getElementById('btn-clear-traffic')?.addEventListener('click', () => {
    trafficHistory = [];
    renderTrafficTable();
  });

  // Filter inputs
  document.getElementById('traffic-search')?.addEventListener('input', renderTrafficTable);
  document.getElementById('rule-search')?.addEventListener('input', renderRulesTable);
});
