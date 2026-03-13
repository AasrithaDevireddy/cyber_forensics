
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config/config');

// Ensure data directory exists
const dataDir = path.dirname(config.paths.db);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(config.paths.db);

/**
 * Enable WAL mode for performance and set pragmas
 */
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

/**
 * Initialize all tables
 */
function initDatabase() {
  // Sessions table — one row per unique attacker session
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      ip_normalized TEXT,
      user_agent TEXT,
      ua_parsed TEXT,
      geo_country TEXT,
      geo_city TEXT,
      geo_region TEXT,
      geo_lat REAL,
      geo_lon REAL,
      isp TEXT,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      request_count INTEGER DEFAULT 1,
      risk_score INTEGER DEFAULT 0,
      risk_level TEXT DEFAULT 'LOW',
      is_bot INTEGER DEFAULT 0,
      fingerprint TEXT,
      hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  // Events table — every single request logged
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      method TEXT,
      path TEXT,
      query TEXT,
      headers TEXT,
      body TEXT,
      payload_hash TEXT,
      status_code INTEGER,
      response_time_ms INTEGER,
      event_type TEXT DEFAULT 'REQUEST',
      attack_type TEXT,
      mitre_tactic TEXT,
      mitre_technique TEXT,
      mitre_id TEXT,
      severity TEXT DEFAULT 'INFO',
      evidence_file TEXT,
      hash TEXT NOT NULL,
      FOREIGN KEY (session_id) REFERENCES sessions(id)
    )
  `);

  // Payloads table — stores raw attack payloads
  db.exec(`
    CREATE TABLE IF NOT EXISTS payloads (
      id TEXT PRIMARY KEY,
      event_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      raw_payload TEXT,
      encoded_payload TEXT,
      payload_type TEXT,
      detected_pattern TEXT,
      timestamp INTEGER NOT NULL,
      hash TEXT NOT NULL,
      FOREIGN KEY (event_id) REFERENCES events(id)
    )
  `);

  // Admin users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      last_login INTEGER
    )
  `);

  // Integrity log — hash chain for tamper detection
  db.exec(`
    CREATE TABLE IF NOT EXISTS integrity_chain (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      record_id TEXT NOT NULL,
      table_name TEXT NOT NULL,
      record_hash TEXT NOT NULL,
      chain_hash TEXT NOT NULL,
      timestamp INTEGER DEFAULT (strftime('%s', 'now'))
    )
  `);

  console.log('[DB] Database initialized successfully');
}

/**
 * Compute SHA-256 hash of data object
 */
function computeHash(data) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(data))
    .digest('hex');
}

/**
 * Get the last chain hash for integrity chaining
 */
function getLastChainHash() {
  const row = db.prepare(
    'SELECT chain_hash FROM integrity_chain ORDER BY id DESC LIMIT 1'
  ).get();
  return row ? row.chain_hash : '0000000000000000000000000000000000000000000000000000000000000000';
}

/**
 * Append to integrity chain
 */
function appendToChain(tableName, recordId, recordHash) {
  const lastHash = getLastChainHash();
  const chainHash = crypto
    .createHash('sha256')
    .update(lastHash + recordHash)
    .digest('hex');
  
  db.prepare(`
    INSERT INTO integrity_chain (record_id, table_name, record_hash, chain_hash)
    VALUES (?, ?, ?, ?)
  `).run(recordId, tableName, recordHash, chainHash);
  
  return chainHash;
}

/**
 * Upsert a session record
 */
function upsertSession(sessionData) {
  const hash = computeHash(sessionData);
  const existing = db.prepare('SELECT id FROM sessions WHERE id = ?').get(sessionData.id);
  
  if (existing) {
    // Update last seen and request count
    db.prepare(`
      UPDATE sessions SET 
        last_seen = ?,
        request_count = request_count + 1,
        risk_score = ?,
        risk_level = ?,
        hash = ?
      WHERE id = ?
    `).run(
      sessionData.last_seen,
      sessionData.risk_score,
      sessionData.risk_level,
      hash,
      sessionData.id
    );
  } else {
    // Insert new session
    db.prepare(`
      INSERT INTO sessions (
        id, ip, ip_normalized, user_agent, ua_parsed, geo_country, geo_city,
        geo_region, geo_lat, geo_lon, first_seen, last_seen, risk_score,
        risk_level, is_bot, fingerprint, hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessionData.id,
      sessionData.ip,
      sessionData.ip_normalized || sessionData.ip,
      sessionData.user_agent,
      JSON.stringify(sessionData.ua_parsed || {}),
      sessionData.geo_country,
      sessionData.geo_city,
      sessionData.geo_region,
      sessionData.geo_lat,
      sessionData.geo_lon,
      sessionData.first_seen,
      sessionData.last_seen,
      sessionData.risk_score,
      sessionData.risk_level,
      sessionData.is_bot ? 1 : 0,
      sessionData.fingerprint,
      hash
    );
    
    appendToChain('sessions', sessionData.id, hash);
  }
}

/**
 * Insert an event record
 */
function insertEvent(eventData) {
  const hash = computeHash(eventData);
  
  db.prepare(`
    INSERT INTO events (
      id, session_id, timestamp, method, path, query, headers, body,
      payload_hash, status_code, response_time_ms, event_type, attack_type,
      mitre_tactic, mitre_technique, mitre_id, severity, evidence_file, hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventData.id,
    eventData.session_id,
    eventData.timestamp,
    eventData.method,
    eventData.path,
    eventData.query ? JSON.stringify(eventData.query) : null,
    JSON.stringify(eventData.headers || {}),
    eventData.body ? JSON.stringify(eventData.body) : null,
    eventData.payload_hash,
    eventData.status_code,
    eventData.response_time_ms,
    eventData.event_type,
    eventData.attack_type,
    eventData.mitre_tactic,
    eventData.mitre_technique,
    eventData.mitre_id,
    eventData.severity,
    eventData.evidence_file,
    hash
  );
  
  appendToChain('events', eventData.id, hash);
}

/**
 * Insert a payload record
 */
function insertPayload(payloadData) {
  const hash = computeHash(payloadData);
  
  db.prepare(`
    INSERT INTO payloads (
      id, event_id, session_id, raw_payload, encoded_payload,
      payload_type, detected_pattern, timestamp, hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    payloadData.id,
    payloadData.event_id,
    payloadData.session_id,
    payloadData.raw_payload,
    payloadData.encoded_payload,
    payloadData.payload_type,
    payloadData.detected_pattern,
    payloadData.timestamp,
    hash
  );
}

/**
 * Query functions for admin dashboard
 */
const queries = {
  // Get all sessions with summary
  getSessions: db.prepare(`
    SELECT s.*, 
      COUNT(e.id) as total_events,
      SUM(CASE WHEN e.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_events,
      SUM(CASE WHEN e.severity = 'HIGH' THEN 1 ELSE 0 END) as high_events
    FROM sessions s
    LEFT JOIN events e ON s.id = e.session_id
    GROUP BY s.id
    ORDER BY s.last_seen DESC
    LIMIT 100
  `),
  
  // Get session by ID
  getSessionById: db.prepare(`
    SELECT * FROM sessions WHERE id = ?
  `),
  
  // Get events for a session
  getEventsBySession: db.prepare(`
    SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC
  `),
  
  // Get recent events across all sessions
  getRecentEvents: db.prepare(`
    SELECT e.*, s.ip, s.geo_country, s.geo_city
    FROM events e
    JOIN sessions s ON e.session_id = s.id
    ORDER BY e.timestamp DESC
    LIMIT 200
  `),
  
  // Get all attack events
  getAttackEvents: db.prepare(`
    SELECT e.*, s.ip, s.geo_country, s.user_agent
    FROM events e
    JOIN sessions s ON e.session_id = s.id
    WHERE e.attack_type IS NOT NULL
    ORDER BY e.timestamp DESC
    LIMIT 500
  `),
  
  // Get payloads for a session
  getPayloadsBySession: db.prepare(`
    SELECT p.*, e.path, e.method
    FROM payloads p
    JOIN events e ON p.event_id = e.id
    WHERE p.session_id = ?
    ORDER BY p.timestamp ASC
  `),
  
  // Stats for dashboard
  getStats: db.prepare(`
  SELECT
    COALESCE((SELECT COUNT(*) FROM sessions), 0) AS total_sessions,
    COALESCE((SELECT COUNT(*) FROM events), 0) AS total_events,
    COALESCE((SELECT COUNT(*) FROM events WHERE attack_type IS NOT NULL), 0) AS attack_events,
    COALESCE((SELECT COUNT(*) FROM sessions WHERE risk_level = 'CRITICAL'), 0) AS critical_sessions,
    COALESCE((SELECT COUNT(*) FROM sessions WHERE risk_level = 'HIGH'), 0) AS high_sessions,
    COALESCE((SELECT COUNT(DISTINCT ip) FROM sessions), 0) AS unique_ips
`),
  
  // Attack type distribution
  getAttackDistribution: db.prepare(`
    SELECT attack_type, COUNT(*) as count
    FROM events
    WHERE attack_type IS NOT NULL
    GROUP BY attack_type
    ORDER BY count DESC
  `),
  
  // Timeline data (last 24h by hour)
  getTimelineData: db.prepare(`
    SELECT 
      strftime('%Y-%m-%d %H:00', datetime(timestamp/1000, 'unixepoch')) as hour,
      COUNT(*) as count
    FROM events
    WHERE timestamp > (strftime('%s', 'now') - 86400) * 1000
    GROUP BY hour
    ORDER BY hour ASC
  `),
  
  // Geo distribution
  getGeoDistribution: db.prepare(`
    SELECT geo_country, COUNT(*) as count
    FROM sessions
    WHERE geo_country IS NOT NULL
    GROUP BY geo_country
    ORDER BY count DESC
    LIMIT 20
  `),
  
  // Integrity chain for verification
  getIntegrityChain: db.prepare(`
    SELECT * FROM integrity_chain ORDER BY id ASC
  `),
  
  // Full report data
  getReportData: (sessionId) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
    const events = db.prepare('SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC').all(sessionId);
    const payloads = db.prepare('SELECT * FROM payloads WHERE session_id = ? ORDER BY timestamp ASC').all(sessionId);
    return { session, events, payloads };
  }
};

module.exports = {
  db,
  initDatabase,
  computeHash,
  upsertSession,
  insertEvent,
  insertPayload,
  queries,
};