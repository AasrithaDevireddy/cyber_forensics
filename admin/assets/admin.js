
const ADMIN_PATH = '/' + window.location.pathname.split('/')[1];
const API_BASE = `${window.location.origin}${ADMIN_PATH}/api`;
const REFRESH_MS = 30_000; // Auto-refresh interval

const state = {
  token:       sessionStorage.getItem('fcs_token') || null,
  charts:      {},         // Chart.js instances keyed by name
  sessions:    [],         // Cached sessions list
  refreshTimer: null,
};

function esc(str) {
  if (str == null) return '';
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

/** Truncate long strings with ellipsis */
function trunc(str, len = 40) {
  if (!str) return '';
  str = String(str);
  return str.length > len ? str.slice(0, len) + '…' : str;
}

/** Format epoch milliseconds to locale string */
function fmtTime(ms) {
  if (!ms) return '—';
  return new Date(ms).toLocaleString(undefined, {
    year:  'numeric', month:  'short',  day:    '2-digit',
    hour:  '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/** Format epoch ms to ISO (for timeline display) */
function fmtISO(ms) {
  if (!ms) return '—';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

/** Return CSS class for severity / risk level */
function riskClass(level) {
  return `risk-${(level || 'INFO').toUpperCase()}`;
}

/** Return color variable for severity */
function severityColor(sev) {
  const map = {
    CRITICAL: 'var(--critical)',
    HIGH:     'var(--high)',
    MEDIUM:   'var(--medium)',
    LOW:      'var(--low)',
    INFO:     'var(--text-dim)',
  };
  return map[(sev || '').toUpperCase()] || 'var(--text-dim)';
}

function startClock() {
  const el = document.getElementById('topbar-clock');
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toUTCString().slice(0, 25) + ' UTC';
  };
  tick();
  setInterval(tick, 1000);
}


/** Perform login — posts credentials, stores JWT */
async function doLogin() {
  const username  = document.getElementById('auth-user').value.trim();
  const password  = document.getElementById('auth-pass').value;
  const errEl     = document.getElementById('auth-error');
  const btn       = document.getElementById('login-submit-btn');

  if (!username || !password) {
    showLoginError('Username and password are required.');
    return;
  }

  btn.textContent = 'AUTHENTICATING…';
  btn.disabled    = true;
  errEl.style.display = 'none';

  try {
    const res  = await fetch(`${API_BASE}/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (data.token) {
      state.token = data.token;
      sessionStorage.setItem('fcs_token', data.token);
      mountApp();
    } else {
      showLoginError(data.error || 'Authentication failed. Access denied.');
    }
  } catch (err) {
    showLoginError('Connection refused. Is the server running?');
  } finally {
    btn.textContent = 'AUTHENTICATE →';
    btn.disabled    = false;
  }
}

function showLoginError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent    = '⚠ ' + msg;
  el.style.display  = 'block';
}

function logout() {
  sessionStorage.removeItem('fcs_token');
  state.token   = null;
  state.sessions = [];
  clearInterval(state.refreshTimer);

  // Destroy charts to free memory
  Object.values(state.charts).forEach(c => c?.destroy?.());
  state.charts = {};

  document.getElementById('app').style.display    = 'none';
  document.getElementById('login-screen').style.display = 'flex';
}


async function api(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${state.token}`,
      'Cache-Control': 'no-cache',
    },
  });

  if (res.status === 401) {
    logout();
    throw new Error('Session expired. Please log in again.');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }

  return res.json();
}


function mountApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display          = 'block';

  startClock();
  loadAll();

  // Auto-refresh
  clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(loadAll, REFRESH_MS);
}

async function loadAll() {
  try {
    await Promise.allSettled([
      loadStats(),
      loadSessions(),
      loadAttacks(),
      loadTimeline(),
      loadPayloads(),
      loadIntegrity(),
    ]);
  } catch (e) {
    console.warn('[Dashboard] Refresh error:', e.message);
  }
}


function showView(name, btn) {
  document.querySelectorAll('.view').forEach(v    => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const view = document.getElementById(`view-${name}`);
  if (view) view.classList.add('active');
  if (btn)  btn.classList.add('active');
}


async function loadStats() {
  try {
    const data = await api('/stats');
    const s    = data.stats || {};

    setText('stat-sessions',  s.total_sessions  || 0);
    setText('stat-events',    s.total_events     || 0);
    setText('stat-attacks',   s.attack_events    || 0);
    setText('stat-unique-ips',s.unique_ips       || 0);

    // Topbar alert chip
    const criticalCount = (s.critical_sessions || 0) + (s.high_sessions || 0);
    const chip = document.getElementById('alert-chip');
    if (chip) {
      chip.textContent = `⚡ ${criticalCount} HIGH+ ALERTS`;
      chip.classList.toggle('visible', criticalCount > 0);
    }

    // Sidebar badge
    setBadge('badge-attacks', s.attack_events || 0);

    // Render all charts
    renderTimelineChart(data.timeline || []);
    renderAttackChart(data.attackDistribution || []);
    renderGeoChart(data.geoDistribution || []);
    renderRiskChart(data.stats || {});

  } catch (e) {
    console.warn('[Stats] Failed:', e.message);
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBadge(id, count) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = count;
  el.classList.toggle('visible', count > 0);
}

/* ── Chart: Activity Timeline ───────────────────────────────────── */
function renderTimelineChart(timeline) {
  const ctx = document.getElementById('chart-timeline');
  if (!ctx) return;

  state.charts.timeline?.destroy();

  state.charts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: timeline.map(t => (t.hour || '').slice(11, 16)),
      datasets: [{
        label:            'Events/Hour',
        data:             timeline.map(t => t.count),
        borderColor:      '#2d7ff9',
        backgroundColor:  'rgba(45, 127, 249, 0.08)',
        fill:             true,
        tension:          0.45,
        pointRadius:      4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#2d7ff9',
        borderWidth:      2,
      }]
    },
    options: {
      responsive:          true,
      maintainAspectRatio: true,
      interaction:         { intersect: false, mode: 'index' },
      plugins: {
        legend: { display: false },
        tooltip: { ...tooltipStyle() },
      },
      scales: {
        x: { ...scaleStyle(), grid: { display: false } },
        y: { ...scaleStyle(), beginAtZero: true },
      },
    }
  });
}

/* ── Chart: Attack Type Doughnut ────────────────────────────────── */
function renderAttackChart(distribution) {
  const ctx = document.getElementById('chart-attacks');
  if (!ctx) return;

  state.charts.attacks?.destroy();

  const COLORS = ['#ff3d57','#ff7b2c','#ffb224','#2d7ff9','#00d084','#8b5cf6','#ec4899','#06b6d4'];

  state.charts.attacks = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels:   distribution.map(d => d.attack_type),
      datasets: [{
        data:            distribution.map(d => d.count),
        backgroundColor: COLORS.slice(0, distribution.length),
        borderWidth:     0,
        hoverOffset:     6,
      }]
    },
    options: {
      responsive:  true,
      cutout:      '65%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color:     '#8899b4',
            font:      { family: "'IBM Plex Mono'", size: 9 },
            padding:   10,
            boxWidth:  10,
            boxHeight: 10,
          },
        },
        tooltip: { ...tooltipStyle() },
      },
    }
  });
}

function renderGeoChart(geo) {
  const ctx = document.getElementById('chart-geo');
  if (!ctx) return;

  state.charts.geo?.destroy();

  state.charts.geo = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: geo.slice(0, 10).map(g => g.geo_country || 'Unknown'),
      datasets: [{
        label:           'Sessions',
        data:            geo.slice(0, 10).map(g => g.count),
        backgroundColor: 'rgba(45, 127, 249, 0.6)',
        borderColor:     'rgba(45, 127, 249, 0.9)',
        borderWidth:     1,
        borderRadius:    4,
      }]
    },
    options: {
      responsive:  true,
      plugins: {
        legend:  { display: false },
        tooltip: { ...tooltipStyle() },
      },
      scales: {
        x: { ...scaleStyle(), grid: { display: false } },
        y: { ...scaleStyle(), beginAtZero: true },
      },
    }
  });
}

function renderRiskChart(stats) {
  const ctx = document.getElementById('chart-risk');
  if (!ctx) return;

  state.charts.risk?.destroy();

  const critical = stats.critical_sessions || 0;
  const high     = stats.high_sessions     || 0;
  const total    = stats.total_sessions    || 0;
  const medium   = Math.max(0, Math.floor((total - critical - high) * 0.3));
  const low      = Math.max(0, total - critical - high - medium);

  state.charts.risk = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels:   ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data:            [critical, high, medium, low],
        backgroundColor: ['#ff3d57', '#ff7b2c', '#ffb224', '#00d084'],
        borderWidth:     0,
        hoverOffset:     4,
      }]
    },
    options: {
      responsive: true,
      cutout:     '60%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color:     '#8899b4',
            font:      { family: "'IBM Plex Mono'", size: 9 },
            padding:   8,
            boxWidth:  10,
            boxHeight: 10,
          },
        },
        tooltip: { ...tooltipStyle() },
      },
    }
  });
}

function scaleStyle() {
  return {
    ticks: { color: '#4a5568', font: { family: "'IBM Plex Mono'", size: 9 } },
    grid:  { color: 'rgba(255,255,255,0.04)' },
    border: { color: 'transparent' },
  };
}

function tooltipStyle() {
  return {
    backgroundColor: '#111c30',
    borderColor:     'rgba(255,255,255,0.08)',
    borderWidth:     1,
    titleColor:      '#e8edf5',
    bodyColor:       '#8899b4',
    titleFont:       { family: "'IBM Plex Mono'", size: 11 },
    bodyFont:        { family: "'IBM Plex Mono'", size: 10 },
    padding:         10,
    cornerRadius:    6,
  };
}


async function loadSessions() {
  try {
    const data = await api('/sessions');
    state.sessions = data.sessions || [];

    const tbody    = document.getElementById('sessions-tbody');
    const countEl  = document.getElementById('sessions-count');
    if (countEl) countEl.textContent = `${state.sessions.length} total`;

    if (!tbody) return;

    if (state.sessions.length === 0) {
      tbody.innerHTML = emptyRow(8, '👁 Waiting for activity…');
      return;
    }

    tbody.innerHTML = state.sessions.map(s => {
      const ua = safeParseJSON(s.ua_parsed) || {};
      return `
        <tr onclick="openSession('${esc(s.id)}')">
          <td class="text-mono" style="color:var(--text-dim)" data-tooltip="${esc(s.id)}">${esc(s.id.slice(0, 10))}…</td>
          <td class="ip-text">${esc(s.ip)}</td>
          <td>${esc(s.geo_country || '?')} / ${esc(s.geo_city || '?')}</td>
          <td class="text-muted truncate" title="${esc(s.user_agent)}">${esc(trunc(ua.browser || s.user_agent, 22))}</td>
          <td class="text-mono">${s.request_count || 0}</td>
          <td><span class="${riskClass(s.risk_level)} risk-badge">${esc(s.risk_level)} ${s.risk_score || 0}</span></td>
          <td class="text-dim text-mono" style="font-size:10px">${fmtTime(s.last_seen)}</td>
          <td>
            <button class="btn-sm btn-sm-primary" onclick="event.stopPropagation();openSession('${esc(s.id)}')">Detail</button>
            <button class="btn-sm btn-sm-success" style="margin-left:4px" onclick="event.stopPropagation();downloadReport('${esc(s.id)}')">PDF</button>
          </td>
        </tr>`;
    }).join('');

  } catch (e) {
    console.warn('[Sessions] Failed:', e.message);
  }
}


async function loadAttacks() {
  try {
    const data    = await api('/attacks');
    const attacks = data.attacks || [];
    const tbody   = document.getElementById('attacks-tbody');

    if (!tbody) return;

    if (attacks.length === 0) {
      tbody.innerHTML = emptyRow(7, '🛡 No attacks recorded yet');
      return;
    }

    tbody.innerHTML = attacks.map(a => `
      <tr>
        <td class="text-mono text-dim" style="font-size:10px;white-space:nowrap">${fmtTime(a.timestamp)}</td>
        <td class="ip-text">${esc(a.ip)}</td>
        <td class="text-muted">${esc(a.geo_country || '?')}</td>
        <td><span class="attack-badge">${esc(a.attack_type)}</span></td>
        <td><span class="mitre-badge">${esc(a.mitre_id || 'N/A')}</span></td>
        <td class="text-mono truncate" title="${esc(a.path)}" style="max-width:180px">${esc(a.path)}</td>
        <td><span class="${riskClass(a.severity)} risk-badge">${esc(a.severity)}</span></td>
      </tr>
    `).join('');

  } catch (e) {
    console.warn('[Attacks] Failed:', e.message);
  }
}


async function loadTimeline() {
  try {
    const data   = await api('/events');
    const events = data.events || [];
    const wrap   = document.getElementById('timeline-wrap');

    if (!wrap) return;

    if (events.length === 0) {
      wrap.innerHTML = `<div class="state-empty"><div class="state-icon">📅</div><div class="state-text">No events captured yet</div></div>`;
      return;
    }

    wrap.innerHTML = events.slice(0, 80).map((e, i) => {
      const color = severityColor(e.severity);
      const isLast = i === Math.min(events.length, 80) - 1;
      return `
        <div class="timeline-entry">
          <div class="timeline-spine">
            <div class="timeline-node" style="border-color:${color};background:${color}22"></div>
            ${!isLast ? '<div class="timeline-line"></div>' : ''}
          </div>
          <div class="timeline-body">
            <div class="timeline-ts">${fmtISO(e.timestamp)}</div>
            <div class="timeline-ev">
              ${e.attack_type ? `<span class="attack-badge">${esc(e.attack_type)}</span> ` : ''}
              <span style="color:var(--accent-bright)">${esc(e.method)}</span>
              <span class="text-muted"> ${esc(trunc(e.path, 60))}</span>
              — <span class="ip-text">${esc(e.ip)}</span>
              <span class="text-dim"> (${esc(e.geo_country || '?')})</span>
              ${e.mitre_id ? `<span class="mitre-badge" style="margin-left:4px">${esc(e.mitre_id)}</span>` : ''}
            </div>
          </div>
        </div>`;
    }).join('');

  } catch (e) {
    console.warn('[Timeline] Failed:', e.message);
  }
}


async function loadPayloads() {
  try {
    const data    = await api('/attacks');
    const attacks = (data.attacks || []).filter(a => a.attack_type);
    const wrap    = document.getElementById('payloads-wrap');

    if (!wrap) return;

    if (attacks.length === 0) {
      wrap.innerHTML = `<div class="state-empty"><div class="state-icon">💉</div><div class="state-text">No attack payloads captured yet</div></div>`;
      return;
    }

    // Also load payload details for richer display
    wrap.innerHTML = attacks.slice(0, 60).map(a => `
      <div class="payload-card">
        <div class="payload-card-header">
          <span class="attack-badge">${esc(a.attack_type)}</span>
          <span class="${riskClass(a.severity)} risk-badge">${esc(a.severity)}</span>
          <span class="mitre-badge">${esc(a.mitre_id || 'N/A')}</span>
          <span class="payload-meta">${esc(a.ip)} · ${fmtISO(a.timestamp)}</span>
        </div>
        <div class="payload-path">
          <span class="text-dim">Method:</span> <span style="color:var(--accent-bright)">${esc(a.method)}</span>
          &nbsp;·&nbsp;
          <span class="text-dim">Path:</span> <span class="text-mono" style="color:var(--text-primary)">${esc(a.path)}</span>
          &nbsp;·&nbsp;
          <span class="text-dim">Country:</span> ${esc(a.geo_country || '?')}
        </div>
        ${a.mitre_technique ? `<div style="font-size:10px;color:var(--medium);margin-bottom:8px;font-family:var(--font-mono)">MITRE: ${esc(a.mitre_technique)}</div>` : ''}
        <div class="payload-raw">
          ── Captured from ${esc(a.method)} ${esc(a.path)} ──
          Attack type: ${esc(a.attack_type)}
          IP: ${esc(a.ip)} | Country: ${esc(a.geo_country || 'Unknown')}
          Hash: ${esc(a.payload_hash || 'N/A')}
        </div>
      </div>
    `).join('');

  } catch (e) {
    console.warn('[Payloads] Failed:', e.message);
  }
}


async function loadIntegrity() {
  try {
    const data   = await api('/integrity');
    const chain  = data.chain || [];
    const tbody  = document.getElementById('integrity-tbody');
    const countEl= document.getElementById('integrity-count');

    if (countEl) countEl.textContent = `${chain.length} entries`;
    if (!tbody)  return;

    if (chain.length === 0) {
      tbody.innerHTML = emptyRow(5, '🔗 No chain entries yet');
      return;
    }

    // Show last 50 entries
    tbody.innerHTML = chain.slice(-50).reverse().map(c => `
      <tr>
        <td class="text-mono" style="color:var(--low)">${c.id}</td>
        <td class="text-mono text-muted">${esc(c.table_name)}</td>
        <td class="text-mono text-dim" style="font-size:10px" data-tooltip="${esc(c.record_hash)}">${c.record_hash.slice(0, 18)}…</td>
        <td class="text-mono" style="color:var(--accent-bright);font-size:10px" data-tooltip="${esc(c.chain_hash)}">${c.chain_hash.slice(0, 18)}…</td>
        <td class="text-mono text-dim" style="font-size:10px">${fmtTime(c.timestamp * 1000)}</td>
      </tr>
    `).join('');

    // Display chain head hash
    const headEl = document.getElementById('chain-head-hash');
    if (headEl && chain.length > 0) {
      headEl.textContent = chain[chain.length - 1].chain_hash;
    }

  } catch (e) {
    console.warn('[Integrity] Failed:', e.message);
  }
}



async function openSession(sessionId) {
  // Open panel
  document.querySelector('.panel-backdrop')?.classList.add('open');
document.querySelector('.session-panel')?.classList.add('open');
document.getElementById('panel-body').innerHTML = `
  <div class="state-loading">
    <div class="spinner"></div>
    <div class="state-text">Loading session data…</div>
  </div>
`;

  try {
    const data = await api(`/sessions/${sessionId}`);
    const { session, events, payloads } = data;

    const ua         = safeParseJSON(session.ua_parsed) || {};
    const riskColor  = severityColor(session.risk_level || 'LOW');

    document.getElementById('panel-body').innerHTML = `

      <!-- Session Overview -->
      <div class="panel-section-label">Session Overview</div>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-key">Session ID</div>
          <div class="meta-val" style="font-size:9px;color:var(--text-dim)">${esc(session.id)}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">IP Address</div>
          <div class="meta-val ip-text">${esc(session.ip)}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Location</div>
          <div class="meta-val">${esc(session.geo_country || '?')} / ${esc(session.geo_city || '?')}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Region</div>
          <div class="meta-val">${esc(session.geo_region || 'Unknown')}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Risk Level</div>
          <div class="meta-val" style="color:${riskColor};font-weight:700">${esc(session.risk_level)} &mdash; ${session.risk_score || 0}/100</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Is Bot</div>
          <div class="meta-val" style="color:${session.is_bot ? 'var(--critical)' : 'var(--low)'}">${session.is_bot ? '⚠ YES — Automated' : '✓ Human Browser'}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">First Seen</div>
          <div class="meta-val" style="font-size:10px">${fmtTime(session.first_seen)}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Last Seen</div>
          <div class="meta-val" style="font-size:10px">${fmtTime(session.last_seen)}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Total Requests</div>
          <div class="meta-val">${session.request_count || 0}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">Geo Coordinates</div>
          <div class="meta-val" style="font-size:10px">${session.geo_lat || '?'}, ${session.geo_lon || '?'}</div>
        </div>
      </div>

      <!-- Browser Fingerprint -->
      <div class="meta-item" style="margin-bottom:10px">
        <div class="meta-key">User Agent</div>
        <div class="meta-val" style="font-size:10px;white-space:normal">${esc(session.user_agent || 'Unknown')}</div>
      </div>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-key">Browser</div>
          <div class="meta-val">${esc(ua.browser || '?')} ${esc(ua.browserVersion || '')}</div>
        </div>
        <div class="meta-item">
          <div class="meta-key">OS</div>
          <div class="meta-val">${esc(ua.os || '?')} ${esc(ua.osVersion || '')}</div>
        </div>
      </div>

      <!-- Fingerprint Hash -->
      <div class="panel-section-label">Session Fingerprint (SHA-256)</div>
      <div class="hash-display">${esc(session.fingerprint || 'N/A')}</div>

      <!-- Report Download -->
      <button class="btn-primary" style="width:100%;margin-bottom:4px" onclick="downloadReport('${esc(session.id)}')">
        ⬇ Download PDF Forensic Report for This Session
      </button>

      <!-- Attack Payloads -->
      ${payloads.length > 0 ? `
        <div class="panel-section-label">Attack Payloads Captured (${payloads.length})</div>
        ${payloads.map(p => `
          <div class="payload-card">
            <div class="payload-card-header">
              <span class="attack-badge">${esc(p.payload_type)}</span>
              <span class="payload-meta">${fmtISO(p.timestamp)}</span>
            </div>
            <div class="payload-raw">${esc(p.raw_payload || '(empty payload)')}</div>
            <div style="margin-top:6px;font-size:9px;color:var(--text-dim);font-family:var(--font-mono)">
              Base64: ${esc(trunc(p.encoded_payload || '', 60))}
            </div>
          </div>
        `).join('')}
      ` : `<div class="panel-section-label">Attack Payloads</div><div class="state-empty" style="padding:20px"><div class="state-text">No attack payloads for this session</div></div>`}

      <!-- Event Log -->
      <div class="panel-section-label">Full Event Log (${events.length} events)</div>
      <div>
        ${events.map((e, i) => {
          const color  = severityColor(e.severity);
          const isLast = i === events.length - 1;
          return `
            <div class="timeline-entry">
              <div class="timeline-spine">
                <div class="timeline-node" style="border-color:${color};background:${color}22"></div>
                ${!isLast ? '<div class="timeline-line"></div>' : ''}
              </div>
              <div class="timeline-body">
                <div class="timeline-ts">${fmtISO(e.timestamp)}</div>
                <div class="timeline-ev">
                  ${e.attack_type ? `<span class="attack-badge">${esc(e.attack_type)}</span> ` : ''}
                  <span style="color:var(--accent-bright)">${esc(e.method)}</span>
                  <span class="text-muted"> ${esc(e.path)}</span>
                  <span class="text-dim"> [${esc(e.status_code || '?')}] ${e.response_time_ms || 0}ms</span>
                  ${e.mitre_id ? `<span class="mitre-badge" style="margin-left:4px">${esc(e.mitre_id)}</span>` : ''}
                </div>
              </div>
            </div>`;
        }).join('')}
      </div>
    `;

  } catch (e) {
    document.getElementById('panel-body').innerHTML = `
      <div class="state-empty">
        <div class="state-icon">⚠</div>
        <div class="state-text">Failed to load session: ${esc(e.message)}</div>
      </div>`;
  }
}

function closePanel() {
  document.querySelector('.panel-backdrop')?.classList.remove('open');
  document.querySelector('.session-panel')?.classList.remove('open');

  const body = document.getElementById('panel-body');
  if (body) {
    setTimeout(() => {
      body.innerHTML = '';
    }, 300);
  }
}


async function downloadFullReport() {

  const res = await fetch(`${API_BASE}/report`, {
    headers: {
      Authorization: `Bearer ${authToken}`
    }
  });

  if (!res.ok) {
    alert("Failed to generate report");
    return;
  }

  const blob = await res.blob();

  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "forensic_report.pdf";

  document.body.appendChild(link);
  link.click();
  link.remove();
}

function downloadFullReport() {
  downloadReport(null);
}


/** Generate empty-state row for a table */
function emptyRow(cols, msg) {
  return `<tr><td colspan="${cols}"><div class="state-empty"><div class="state-icon">…</div><div class="state-text">${msg}</div></div></td></tr>`;
}

/** Safely parse a JSON string without throwing */
function safeParseJSON(str) {
  try { return JSON.parse(str); }
  catch { return null; }
}



document.addEventListener('keydown', e => {
  // Enter on login form
  if (e.key === 'Enter' && document.getElementById('login-screen').style.display !== 'none') {
    doLogin();
    return;
  }
  // Escape closes panel
  if (e.key === 'Escape') {
    closePanel();
  }
});

// Bind close button
document.addEventListener('click', (e) => {
  // Close button inside panel
  if (e.target.closest('.panel-close')) {
    closePanel();
  }

  // Clicking backdrop closes panel
  if (e.target.id === 'panel-backdrop') {
    closePanel();
  }
});

// Ensure panel closes cleanly
function closePanel() {
  const backdrop = document.getElementById('panel-backdrop');
  const panel    = document.getElementById('session-panel');
  const body     = document.getElementById('panel-body');

  if (backdrop) backdrop.classList.remove('open');
  if (panel)    panel.classList.remove('open');

  // Optional: clear content after animation
  setTimeout(() => {
    if (body) body.innerHTML = '';
  }, 250);
}

document.addEventListener('click', (e) => {
  // Close button (×)
  if (e.target.closest('.panel-close')) {
    closePanel();
    return;
  }

  // Backdrop click closes panel
  if (e.target.classList.contains('panel-backdrop')) {
    closePanel();
  }
});

document.addEventListener('click', (e) => {

  if (e.target.closest('.panel-close')) {
    closePanel();
    return;
  }

  // backdrop click
  if (e.target.classList.contains('panel-backdrop')) {
    closePanel();
  }
});

document.addEventListener("DOMContentLoaded", () => {

  const btn = document.getElementById("btn-download-report");

  if (btn) {
    btn.addEventListener("click", () => {
      downloadFullReport();
    });
  }

});
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("btn-download-report");

  if (btn) {
    btn.addEventListener("click", () => {
      downloadReport();
    });
  }
});

if (state.token) {
  // Attempt to restore session; if expired the first API call will trigger logout()
  mountApp();
}

// expose functions to HTML buttons
window.downloadReport = downloadReport;
window.downloadFullReport = downloadFullReport;
window.logout = logout;
window.openSession = openSession;