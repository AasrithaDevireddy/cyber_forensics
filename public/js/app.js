/**
 * TechVault Solutions — Frontend Application JS
 * public/js/app.js
 *
 * This is the PUBLIC-FACING JavaScript for the fake business website.
 * It behaves like a real SaaS product frontend.
 *
 * Everything here is intentionally normal — no monitoring code.
 * All monitoring happens server-side invisibly.
 */

/* ═══════════════════════════════════════════════════════════════════
   GLOBAL CONFIG
═══════════════════════════════════════════════════════════════════ */
const TV = {
  apiBase: '/api',
  version: '4.2.1',
  env:     'production',
};

/* ═══════════════════════════════════════════════════════════════════
   UTILITIES
═══════════════════════════════════════════════════════════════════ */

function $(sel, ctx = document) { return ctx.querySelector(sel); }
function $$(sel, ctx = document) { return [...ctx.querySelectorAll(sel)]; }

function show(el) { if (el) el.style.display = 'block'; }
function hide(el) { if (el) el.style.display = 'none'; }

function showAlert(containerId, message, type = 'error') {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.textContent = message;
  el.className   = `alert alert-${type}`;
  el.style.display = 'block';
}

function hideAlert(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.style.display = 'none';
}

/** Generic fetch wrapper with JSON handling */
async function apiFetch(endpoint, options = {}) {
  const defaults = {
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
  };
  const merged = { ...defaults, ...options };
  if (merged.body && typeof merged.body === 'object') {
    merged.body = JSON.stringify(merged.body);
  }
  const res  = await fetch(TV.apiBase + endpoint, merged);
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

/* ═══════════════════════════════════════════════════════════════════
   NAVBAR
═══════════════════════════════════════════════════════════════════ */

function initNavbar() {
  // Mobile menu toggle
  const toggle = document.getElementById('mobile-menu-toggle');
  const navLinks = document.getElementById('nav-links-list');
  if (toggle && navLinks) {
    toggle.addEventListener('click', () => {
      navLinks.classList.toggle('open');
      toggle.setAttribute('aria-expanded', navLinks.classList.contains('open'));
    });
  }

  // Sticky navbar shadow on scroll
  window.addEventListener('scroll', () => {
    const nav = document.querySelector('.navbar');
    if (nav) nav.classList.toggle('scrolled', window.scrollY > 10);
  }, { passive: true });

  // Smooth scroll for anchor links
  $$('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
}

/* ═══════════════════════════════════════════════════════════════════
   HOMEPAGE
═══════════════════════════════════════════════════════════════════ */

function initHomepage() {
  if (!document.getElementById('hero-section')) return;

  // Animate stats counter
  animateCounters();

  // Scroll reveal for feature cards
  initScrollReveal();

  // Fake live activity ticker
  initActivityTicker();
}

/** Animate number counters on hero stats */
function animateCounters() {
  const counters = $$('[data-count-to]');
  if (!counters.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const el     = entry.target;
      const target = parseInt(el.dataset.countTo, 10);
      const suffix = el.dataset.suffix || '';
      let current  = 0;
      const step   = Math.ceil(target / 60);

      const interval = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current.toLocaleString() + suffix;
        if (current >= target) clearInterval(interval);
      }, 20);

      observer.unobserve(el);
    });
  }, { threshold: 0.5 });

  counters.forEach(c => observer.observe(c));
}

/** Fade-in elements as they scroll into view */
function initScrollReveal() {
  const items = $$('.reveal');
  if (!items.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });

  items.forEach(el => observer.observe(el));
}

/** Show fake live activity notifications */
function initActivityTicker() {
  const ticker = document.getElementById('activity-ticker');
  if (!ticker) return;

  const activities = [
    'Acme Corp deployed 3 new servers in us-east-1',
    'GlobalTech reduced infrastructure costs by 34%',
    'New integration: Kubernetes auto-scaling enabled',
    'SkyNet Analytics processed 2.4TB in 0.8 seconds',
    'Zenith Digital upgraded to Enterprise plan',
    'RedBrick Co. achieved 99.97% uptime this month',
    'DataFlow Inc. migrated 12TB to TechVault storage',
    'API gateway processed 14.2M requests in the last hour',
  ];

  let idx = 0;

  function showNext() {
    ticker.style.opacity = '0';
    ticker.style.transform = 'translateY(-8px)';

    setTimeout(() => {
      ticker.textContent = '● ' + activities[idx % activities.length];
      ticker.style.opacity  = '1';
      ticker.style.transform = 'translateY(0)';
      idx++;
    }, 300);
  }

  showNext();
  setInterval(showNext, 4000);
}

/* ═══════════════════════════════════════════════════════════════════
   LOGIN PAGE
═══════════════════════════════════════════════════════════════════ */

function initLoginPage() {
  const form = document.getElementById('login-form');
  if (!form) return;

  form.addEventListener('submit', async e => {
    e.preventDefault();
    await handleLogin();
  });

  // Also init register form if present on the page
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async e => {
      e.preventDefault();
      await handleRegister();
    });
  }

  // Tab switching
  $$('.auth-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $$('.auth-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const target = tab.dataset.target;
      $$('.auth-panel').forEach(p => {
        p.style.display = p.id === target ? 'block' : 'none';
      });
    });
  });
}

async function handleLogin() {
  const username  = document.getElementById('username')?.value?.trim();
  const password  = document.getElementById('password')?.value;
  const btn       = document.getElementById('login-btn');
  const remember  = document.getElementById('remember')?.checked;

  hideAlert('login-alert');

  if (!username || !password) {
    showAlert('login-alert', 'Please enter your username and password.', 'error');
    return;
  }

  // Disable button while request is in flight
  if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }

  try {
    const { ok, status, data } = await apiFetch('/auth/login', {
      method: 'POST',
      body:   { username, password, remember },
    });

    if (data.success) {
      showAlert('login-alert', 'Login successful! Redirecting to dashboard…', 'success');
      setTimeout(() => { window.location.href = '/dashboard'; }, 1500);
    } else {
      // Show whatever error the server returns (fake SQL errors, etc.)
      const msg = data.error || data.message || 'Invalid username or password.';
      showAlert('login-alert', msg, 'error');

      // If remaining attempts info is present, show it
      if (data.remaining_attempts !== undefined) {
        const extra = document.getElementById('login-remaining');
        if (extra) {
          extra.textContent = `${data.remaining_attempts} attempt(s) remaining before lockout.`;
          extra.style.display = 'block';
        }
      }
    }
  } catch (err) {
    showAlert('login-alert', 'Network error. Please check your connection and try again.', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
  }
}

async function handleRegister() {
  const username = document.getElementById('reg-username')?.value?.trim();
  const email    = document.getElementById('reg-email')?.value?.trim();
  const password = document.getElementById('reg-password')?.value;
  const confirm  = document.getElementById('reg-confirm')?.value;
  const btn      = document.getElementById('register-btn');

  hideAlert('register-alert');

  if (!username || !email || !password) {
    showAlert('register-alert', 'All fields are required.', 'error');
    return;
  }

  if (password !== confirm) {
    showAlert('register-alert', 'Passwords do not match.', 'error');
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Creating account…'; }

  try {
    const { ok, data } = await apiFetch('/auth/register', {
      method: 'POST',
      body:   { username, email, password },
    });

    if (data.success) {
      showAlert('register-alert', data.message || 'Account created! Check your email to verify.', 'success');
    } else {
      showAlert('register-alert', data.error || 'Registration failed. Please try again.', 'error');
    }
  } catch {
    showAlert('register-alert', 'Network error. Please try again.', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Create Account'; }
  }
}

/* ═══════════════════════════════════════════════════════════════════
   DASHBOARD PAGE
═══════════════════════════════════════════════════════════════════ */

function initDashboard() {
  const dashEl = document.getElementById('dashboard-main');
  if (!dashEl) return;

  // Load fake dashboard data
  loadDashboardStats();
  loadRecentActivity();
  loadServerStatus();

  // Render fake charts
  renderUsageChart();
  renderRevenueChart();

  // Auto-refresh dashboard data every 45 seconds
  setInterval(() => {
    loadDashboardStats();
    loadRecentActivity();
  }, 45_000);

  // Sidebar navigation
  $$('.dash-nav-item').forEach(item => {
    item.addEventListener('click', () => {
      $$('.dash-nav-item').forEach(n => n.classList.remove('active'));
      item.classList.add('active');
    });
  });
}

/** Populate fake stat cards with realistic-looking numbers */
function loadDashboardStats() {
  const stats = {
    'stat-requests':   (Math.floor(Math.random() * 500) + 14200).toLocaleString(),
    'stat-users':      (Math.floor(Math.random() * 10)  + 2847).toLocaleString(),
    'stat-storage':    (Math.floor(Math.random() * 50)  + 847) + ' GB',
    'stat-uptime':     '99.' + (Math.floor(Math.random() * 9) + 90) + '%',
    'stat-bandwidth':  (Math.floor(Math.random() * 100) + 2340) + ' GB',
    'stat-latency':    (Math.floor(Math.random() * 30)  + 12) + 'ms',
  };

  Object.entries(stats).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  });
}

function loadRecentActivity() {
  const container = document.getElementById('recent-activity');
  if (!container) return;

  const activities = [
    { icon: '🚀', text: 'Auto-scaling triggered for us-east-1 cluster',         time: '2 min ago',  type: 'info' },
    { icon: '✅', text: 'SSL certificate renewed for api.techvault.io',          time: '18 min ago', type: 'success' },
    { icon: '📦', text: 'Deployment v4.2.1 completed across 12 nodes',          time: '1 hr ago',   type: 'success' },
    { icon: '⚠️', text: 'High CPU usage detected on sa-east-1 (resolved)',      time: '2 hr ago',   type: 'warning' },
    { icon: '👤', text: 'New user James K. joined the Enterprise workspace',    time: '3 hr ago',   type: 'info' },
    { icon: '💾', text: 'Automated backup completed — 847 GB archived',         time: '4 hr ago',   type: 'success' },
    { icon: '🔄', text: 'Database migration completed (0 errors)',              time: '6 hr ago',   type: 'success' },
    { icon: '📊', text: 'Monthly analytics report generated and emailed',       time: '8 hr ago',   type: 'info' },
  ];

  container.innerHTML = activities.map(a => `
    <div class="activity-item activity-${a.type}">
      <span class="activity-icon">${a.icon}</span>
      <div class="activity-content">
        <p>${a.text}</p>
        <span class="activity-time">${a.time}</span>
      </div>
    </div>
  `).join('');
}

function loadServerStatus() {
  const container = document.getElementById('server-status');
  if (!container) return;

  const servers = [
    { region: 'us-east-1',   status: 'online',  latency: '12ms',  load: '67%' },
    { region: 'eu-west-2',   status: 'online',  latency: '28ms',  load: '45%' },
    { region: 'ap-south-1',  status: 'online',  latency: '89ms',  load: '31%' },
    { region: 'us-west-2',   status: 'online',  latency: '18ms',  load: '72%' },
    { region: 'sa-east-1',   status: 'warning', latency: '142ms', load: '91%' },
    { region: 'af-south-1',  status: 'online',  latency: '67ms',  load: '22%' },
  ];

  const statusIcon = { online: '●', warning: '⚠', offline: '✕' };

  container.innerHTML = servers.map(s => `
    <div class="server-row">
      <span class="server-status-dot status-${s.status}">${statusIcon[s.status]}</span>
      <span class="server-region">${s.region}</span>
      <span class="server-latency">${s.latency}</span>
      <div class="server-load-bar">
        <div class="server-load-fill load-${parseFloat(s.load) > 80 ? 'high' : 'normal'}" style="width:${s.load}"></div>
      </div>
      <span class="server-load-pct">${s.load}</span>
    </div>
  `).join('');
}

/** Fake CPU/request usage chart */
function renderUsageChart() {
  const ctx = document.getElementById('usage-chart');
  if (!ctx || typeof Chart === 'undefined') return;

  const labels = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const data   = labels.map(() => Math.floor(Math.random() * 40) + 30);

  new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label:            'Request Load (%)',
        data,
        borderColor:      '#4f46e5',
        backgroundColor:  'rgba(79,70,229,0.1)',
        fill:             true,
        tension:          0.4,
        pointRadius:      2,
        borderWidth:      2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid:  { color: 'rgba(0,0,0,0.05)' },
          ticks: { font: { size: 10 }, maxTicksLimit: 8 },
        },
        y: {
          grid:        { color: 'rgba(0,0,0,0.05)' },
          ticks:       { font: { size: 10 } },
          beginAtZero: true,
          max:         100,
        },
      },
    },
  });
}

/** Fake revenue bar chart */
function renderRevenueChart() {
  const ctx = document.getElementById('revenue-chart');
  if (!ctx || typeof Chart === 'undefined') return;

  const months  = ['Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec', 'Jan'];
  const revenue = [42000, 48000, 51000, 55000, 62000, 71000, 78000];

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: months,
      datasets: [{
        label:           'Revenue ($)',
        data:            revenue,
        backgroundColor: 'rgba(79,70,229,0.7)',
        borderColor:     'rgba(79,70,229,0.9)',
        borderWidth:     1,
        borderRadius:    6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid:  { display: false },
          ticks: { font: { size: 11 } },
        },
        y: {
          grid:        { color: 'rgba(0,0,0,0.05)' },
          ticks:       { font: { size: 10 }, callback: v => '$' + (v/1000).toFixed(0) + 'k' },
          beginAtZero: true,
        },
      },
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   UPLOAD PAGE
═══════════════════════════════════════════════════════════════════ */

function initUploadPage() {
  const dropzone = document.getElementById('dropzone');
  if (!dropzone) return;

  const fileInput    = document.getElementById('file-input');
  const uploadBtn    = document.getElementById('upload-btn');
  const fileList     = document.getElementById('file-list');
  const progressWrap = document.getElementById('upload-progress');
  const progressBar  = document.getElementById('progress-bar');
  const progressText = document.getElementById('progress-text');

  let selectedFiles = [];

  // Drag and Drop
  ['dragenter', 'dragover'].forEach(event => {
    dropzone.addEventListener(event, e => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach(event => {
    dropzone.addEventListener(event, e => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
    });
  });

  dropzone.addEventListener('drop', e => {
    handleFileSelect([...e.dataTransfer.files]);
  });

  dropzone.addEventListener('click', () => fileInput?.click());

  fileInput?.addEventListener('change', () => {
    handleFileSelect([...fileInput.files]);
  });

  function handleFileSelect(files) {
    if (!files.length) return;
    selectedFiles = files;

    fileList.innerHTML = files.map(f => `
      <div class="file-item">
        <span class="file-icon">${getFileIcon(f.name)}</span>
        <div class="file-info">
          <span class="file-name">${escapeHtml(f.name)}</span>
          <span class="file-size">${formatBytes(f.size)}</span>
        </div>
        <span class="file-status pending">Pending</span>
      </div>
    `).join('');

    fileList.style.display = 'block';
    if (uploadBtn) uploadBtn.disabled = false;
  }

  uploadBtn?.addEventListener('click', async () => {
    if (!selectedFiles.length) return;

    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Uploading…';
    progressWrap.style.display = 'block';

    for (let i = 0; i < selectedFiles.length; i++) {
      const file   = selectedFiles[i];
      const pct    = Math.round(((i + 1) / selectedFiles.length) * 100);
      progressText.textContent = `Uploading ${file.name}…`;

      const formData = new FormData();
      formData.append('file', file);

      try {
        // Fake progress animation
        await animateProgress(progressBar, pct - (100 / selectedFiles.length), pct);

        const res  = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();

        // Update file item status
        const items = fileList.querySelectorAll('.file-item');
        if (items[i]) {
          const statusEl = items[i].querySelector('.file-status');
          if (statusEl) {
            statusEl.textContent = data.success ? '✓ Uploaded' : '✗ Failed';
            statusEl.className   = `file-status ${data.success ? 'success' : 'error'}`;
          }
        }

      } catch {
        const items = fileList.querySelectorAll('.file-item');
        if (items[i]) {
          const statusEl = items[i].querySelector('.file-status');
          if (statusEl) { statusEl.textContent = '✗ Error'; statusEl.className = 'file-status error'; }
        }
      }
    }

    progressBar.style.width  = '100%';
    progressText.textContent = 'All files uploaded successfully!';
    uploadBtn.textContent    = 'Upload More Files';
    uploadBtn.disabled       = false;
    selectedFiles = [];
  });
}

function animateProgress(bar, from, to) {
  return new Promise(resolve => {
    const steps    = 20;
    const stepPct  = (to - from) / steps;
    let   current  = from;
    const interval = setInterval(() => {
      current += stepPct;
      bar.style.width = Math.min(current, to) + '%';
      if (current >= to) { clearInterval(interval); resolve(); }
    }, 30);
  });
}

function getFileIcon(filename) {
  const ext = filename.split('.').pop()?.toLowerCase();
  const icons = {
    pdf: '📄', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊',
    csv: '📊', png: '🖼', jpg: '🖼', jpeg: '🖼', gif: '🖼',
    mp4: '🎬', mp3: '🎵', zip: '🗜', tar: '🗜', gz: '🗜',
    js:  '⚙', py: '🐍', php: '🔷', sh: '💻', txt: '📃',
  };
  return icons[ext] || '📁';
}

function formatBytes(bytes) {
  if (bytes < 1024)         return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

/* ═══════════════════════════════════════════════════════════════════
   SEARCH / API DEMO
═══════════════════════════════════════════════════════════════════ */

function initSearch() {
  const input = document.getElementById('search-input');
  const btn   = document.getElementById('search-btn');
  const results = document.getElementById('search-results');

  if (!input) return;

  const doSearch = async () => {
    const q = input.value.trim();
    if (!q) return;

    try {
      const res  = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();

      if (results) {
        results.innerHTML = data.results.length
          ? data.results.map(r => `
              <div class="search-result">
                <a href="${escapeHtml(r.url)}">${escapeHtml(r.title)}</a>
                <p>${escapeHtml(r.url)}</p>
              </div>`).join('')
          : '<p class="no-results">No results found.</p>';
        results.style.display = 'block';
      }
    } catch {
      if (results) {
        results.innerHTML = '<p class="search-error">Search is temporarily unavailable.</p>';
      }
    }
  };

  btn?.addEventListener('click', doSearch);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
}

/* ═══════════════════════════════════════════════════════════════════
   CONTACT FORM
═══════════════════════════════════════════════════════════════════ */

function initContactForm() {
  const form = document.getElementById('contact-form');
  if (!form) return;

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const btn = form.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }

    // Simulate submission (no real endpoint)
    await new Promise(r => setTimeout(r, 1200));
    showAlert('contact-alert', 'Thank you! We\'ll be in touch within 24 hours.', 'success');
    form.reset();
    if (btn) { btn.disabled = false; btn.textContent = 'Send Message'; }
  });
}

/* ═══════════════════════════════════════════════════════════════════
   INIT — runs on DOMContentLoaded
═══════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  initNavbar();
  initHomepage();
  initLoginPage();
  initDashboard();
  initUploadPage();
  initSearch();
  initContactForm();
});