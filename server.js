'use strict';

const express = require('express');
const http    = require('http');
const path    = require('path');
const config  = require('./config/config');

// ── Initialize DB ────────────────────────────────────────────────
const { initDatabase } = require('./forensics/database');
initDatabase();

// ── Load middleware & routes ──────────────────────────────────────
const stealthMiddleware = require('./middleware/stealth');
const publicRoutes      = require('./routes/publicRoutes');
const adminRoutes       = require('./routes/adminRoutes');

// ================================================================
// PUBLIC APP (Port 3000)
// ================================================================
const publicApp = express();

publicApp.set('trust proxy', 1);
publicApp.use(express.json({ limit: '10mb' }));
publicApp.use(express.urlencoded({ extended: true }));

// Static fake site
publicApp.use(express.static(path.join(__dirname, 'public'), {
  index: false,
}));

// Stealth capture
publicApp.use(stealthMiddleware);

// Fake business routes
publicApp.use('/', publicRoutes);

// Public fallback
publicApp.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

/// ═══════════════════════════════════════════════════════
// ADMIN APP (Port 3001)
// ═══════════════════════════════════════════════════════

const adminApp = express();

adminApp.set('trust proxy', 1);
adminApp.use(express.json({ limit: '5mb' }));
adminApp.use(express.urlencoded({ extended: true }));

// Static assets
adminApp.use('/assets', express.static(path.join(__dirname, 'admin/assets'), {
  etag: false,
}));

adminApp.get('/ping', (req, res) => res.send('pong'));

// 🔐 Mount admin UI + API UNDER SECRET PATH ONLY
// Admin UI
adminApp.use(`/${config.admin.secretPath}`, adminRoutes);

// Admin API
adminApp.use('/api', adminRoutes);
adminApp.use((req, res) => res.status(404).send('Not Found'));

// ================================================================
// START SERVERS
// ================================================================
const publicServer = http.createServer(publicApp);
const adminServer  = http.createServer(adminApp);

publicServer.listen(config.port, () => {
  console.log(`Public Website  : http://localhost:${config.port}`);
});

adminServer.listen(config.adminPort, () => {
  console.log(`Admin Dashboard : http://localhost:${config.adminPort}/${config.admin.secretPath}/`);
  console.log(`Admin API       : http://localhost:${config.adminPort}/api`);
});

// ── Graceful shutdown ───────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n[Server] Received ${signal}. Shutting down gracefully...`);
  publicServer.close(() => {
    adminServer.close(() => {
      console.log('[Server] All connections closed. Goodbye.');
      process.exit(0);
    });
  });

  // Force exit after 10s if connections hang
  setTimeout(() => {
    console.error('[Server] Force exit after timeout.');
    process.exit(1);
  }, 10_000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Catch unhandled rejections — never crash the server ────────────
process.on('unhandledRejection', (reason) => {
  console.error('[UnhandledRejection]', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[UncaughtException]', err.message);
  // Don't exit — keep the honeypot alive
});

// ─────────────────────────────────────────────────────────────────
function printBanner() {
  const line = '═'.repeat(60);
  console.log(`
${line}
  Anti-Honeypot Cyber Forensics System  v1.0.0
  Powered by TechVault Solutions (Decoy Layer Active)
${line}
  Public Website  : http://localhost:${config.port}
  Environment     : ${config.nodeEnv}`);
}