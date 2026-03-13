/**
 * Forensic Engine — Core Event Processor
 * Order-correct + Transaction-safe version
 */

const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const config = require('../config/config');
const {
  db,
  upsertSession,
  insertEvent,
  insertPayload,
  computeHash
} = require('./database');
const { getMitreEntry } = require('./mitreMapper');
const { calculateRiskScore } = require('./riskScorer');

/* ------------------------------------------------------------------ */
/*  Setup                                                             */
/* ------------------------------------------------------------------ */

if (!fs.existsSync(config.paths.evidence)) {
  fs.mkdirSync(config.paths.evidence, { recursive: true });
}

const sessionCache = new Map();
const forensicBus = new EventEmitter();
forensicBus.setMaxListeners(100);

/* ------------------------------------------------------------------ */
/*  Evidence File                                                     */
/* ------------------------------------------------------------------ */

function saveEvidenceFile(sessionId, eventId, payload) {
  try {
    const filename = `${sessionId}_${eventId}_${Date.now()}.json`;
    const filepath = path.join(config.paths.evidence, filename);

    fs.writeFileSync(
      filepath,
      JSON.stringify(
        {
          sessionId,
          eventId,
          timestamp: new Date().toISOString(),
          payload,
          hash: computeHash(payload)
        },
        null,
        2
      )
    );

    return filename;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  Core Processor                                                    */
/* ------------------------------------------------------------------ */

async function processEvent(data) {
  try {
    const { fingerprint: fp, analysis, req, statusCode, responseTime } = data;

    const now = Date.now();
    const eventId = uuidv4();

    /* ──────────────────────────────── */
    /* 1️⃣ SESSION BUILD               */
    /* ──────────────────────────────── */

    let cached = sessionCache.get(fp.sessionId);

    const sessionData = {
      id: fp.sessionId,
      ip: fp.ip,
      ip_normalized: fp.ip,
      user_agent: fp.userAgent,
      ua_parsed: fp.uaParsed,
      geo_country: fp.geo?.country,
      geo_city: fp.geo?.city,
      geo_region: fp.geo?.region,
      geo_lat: fp.geo?.lat,
      geo_lon: fp.geo?.lon,
      first_seen: cached ? cached.first_seen : now,
      last_seen: now,
      request_count: cached ? cached.request_count + 1 : 1,
      is_bot: analysis?.isBot || false,
      fingerprint: fp.fingerprint,
      risk_score: 0,
      risk_level: 'LOW'
    };

    if (!cached) {
      cached = { ...sessionData, events: [] };
    }

    /* ──────────────────────────────── */
    /* 2️⃣ MITRE + ATTACK              */
    /* ──────────────────────────────── */

    let mitreEntry = null;
    let attackType = null;
    let severity = 'INFO';

    if (analysis?.primaryAttack) {
      attackType = analysis.primaryAttack;
      mitreEntry = getMitreEntry(attackType);
      severity = mitreEntry?.severity || 'HIGH';
    } else if (analysis?.isBot) {
      attackType = 'BOT_SCAN';
      mitreEntry = getMitreEntry('BOT_SCAN');
      severity = 'MEDIUM';
    }

    /* ──────────────────────────────── */
    /* 3️⃣ BUILD EVENT RECORD          */
    /* ──────────────────────────────── */

    const safeHeaders = { ...req.headers };
    delete safeHeaders.authorization;
    delete safeHeaders.cookie;

    const eventRecord = {
      id: eventId,
      session_id: fp.sessionId,
      timestamp: now,
      method: req.method,
      path: req.path,
      query: req.query,
      headers: safeHeaders,
      body: req.body,
      payload_hash: req.body ? computeHash(req.body) : null,
      status_code: statusCode,
      response_time_ms: responseTime,
      event_type: attackType ? 'ATTACK' : 'REQUEST',
      attack_type: attackType,
      mitre_tactic: mitreEntry?.tactic || null,
      mitre_technique: mitreEntry?.technique || null,
      mitre_id: mitreEntry?.id || null,
      severity,
      evidence_file: null
    };

    if (attackType && (req.body || req.query)) {
      eventRecord.evidence_file = saveEvidenceFile(
        fp.sessionId,
        eventId,
        {
          method: req.method,
          path: req.path,
          query: req.query,
          body: req.body,
          headers: safeHeaders,
          attackType,
          detections: analysis?.detections
        }
      );
    }

    /* ──────────────────────────────── */
    /* 4️⃣ RISK CALCULATION            */
    /* ──────────────────────────────── */

    cached.events.push(eventRecord);

    const riskResult = calculateRiskScore({
      ...sessionData,
      events: cached.events
    });

    sessionData.risk_score = riskResult.score;
    sessionData.risk_level = riskResult.level;

    /* ──────────────────────────────── */
    /* 5️⃣ TRANSACTIONAL DB WRITE      */
    /* ORDER: session → event → payload*/
    /* ──────────────────────────────── */

    const transaction = db.transaction(() => {
      upsertSession(sessionData);
      insertEvent(eventRecord);

      if (analysis?.detections?.length) {
        for (const detection of analysis.detections) {
          insertPayload({
            id: uuidv4(),
            event_id: eventId,
            session_id: fp.sessionId,
            raw_payload: detection.value,
            encoded_payload: Buffer.from(detection.value).toString('base64'),
            payload_type: detection.type,
            detected_pattern: detection.type,
            timestamp: now
          });
        }
      }
    });

    transaction();

    /* ──────────────────────────────── */
    /* 6️⃣ CACHE UPDATE                */
    /* ──────────────────────────────── */

    sessionCache.set(fp.sessionId, cached);

    if (sessionCache.size > 1000) {
      const oldest = sessionCache.keys().next().value;
      sessionCache.delete(oldest);
    }

  } catch (error) {
    console.error('[Forensic Engine Error]', error.message);
  }
}

/* ------------------------------------------------------------------ */

forensicBus.on('event', processEvent);

module.exports = { forensicBus };