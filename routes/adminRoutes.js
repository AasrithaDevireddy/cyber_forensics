'use strict';

const express = require('express');
const router  = express.Router();
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const config = require('../config/config');
const { queries } = require('../forensics/database');
const { generateForensicReport } = require('../forensics/reportGenerator');

/* ───────────────── JWT AUTH ───────────────── */

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    req.admin = jwt.verify(auth.slice(7), config.jwt.secret);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* ───────────────── ADMIN UI ───────────────── */
/* This serves the dashboard HTML */

router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../admin/index.html'));
});

/* ───────────────── AUTH ───────────────── */
/* POST <secret>/api/login */

router.post('/api/login', express.json(), async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  if (username !== config.admin.username) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const stored = config.admin.password;
  const ok = stored.startsWith('$2')
    ? await bcrypt.compare(password, stored)
    : password === stored;

  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { username, role: 'admin' },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );

  res.json({ token });
});

/* ───────────────── DASHBOARD DATA ───────────────── */
/* All APIs are under <secret>/api/... */

router.get('/api/stats', requireAuth, (req, res) => {
  try {
    res.json({
      stats: queries.getStats.get() || {},
      attackDistribution: queries.getAttackDistribution.all() || [],
      geoDistribution: queries.getGeoDistribution.all() || [],
      timeline: queries.getTimelineData.all() || []
    });
  } catch (err) {
    console.error('[STATS ERROR]', err);
    res.status(500).json({ error: 'Stats failed' });
  }
});

router.get('/api/sessions', requireAuth, (req, res) => {
  res.json({ sessions: queries.getSessions.all() });
});

router.get('/api/sessions/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const session = queries.getSessionById.get(id);

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  res.json({
    session,
    events: queries.getEventsBySession.all(id),
    payloads: queries.getPayloadsBySession.all(id)
  });
});

router.get('/api/events', requireAuth, (req, res) => {
  res.json({ events: queries.getRecentEvents.all() });
});

router.get('/api/attacks', requireAuth, (req, res) => {
  res.json({ attacks: queries.getAttackEvents.all() });
});

router.get('/api/integrity', requireAuth, (req, res) => {
  res.json({ chain: queries.getIntegrityChain.all() });
});

/* ───────────────── PDF REPORT ───────────────── */
/* GET <secret>/api/report OR /api/report/:sessionId */

router.get('/api/report/:sessionId?', requireAuth, async (req, res) => {
  try {
    const file = await generateForensicReport(req.params.sessionId || null);
    res.download(file);
  } catch (err) {
    console.error('[PDF ERROR]', err.message);
    res.status(500).json({ error: 'PDF generation failed' });
  }
});

module.exports = router;