

const SCORE_WEIGHTS = {
  // Attack types
  SQL_INJECTION: 30,
  COMMAND_INJECTION: 40,
  FILE_UPLOAD_MALICIOUS: 35,
  XSS: 15,
  XSS_STORED: 25,
  PATH_TRAVERSAL: 20,
  BRUTE_FORCE: 20,
  CREDENTIAL_STUFFING: 25,
  DIRECTORY_SCAN: 10,
  BOT_SCAN: 5,
  XXEI: 35,
  SSRF: 30,
  HEADER_INJECTION: 15,
  CSRF: 10,
  RECONNAISSANCE: 3,
  
  // Behavioral modifiers
  HIGH_REQUEST_RATE: 10,      // > 60 req/min
  ODD_HOURS: 5,               // Between 2-5 AM UTC
  TOR_EXIT_NODE: 20,          // Known Tor IP (future: API check)
  BOT_USER_AGENT: 15,
  NO_REFERER: 5,              // No referer header on internal nav
  MULTIPLE_ATTACK_TYPES: 15,  // Using >2 different attack types
};

const RISK_LEVELS = [
  { threshold: 0, level: 'LOW', color: '#22c55e' },
  { threshold: 20, level: 'MEDIUM', color: '#f59e0b' },
  { threshold: 40, level: 'HIGH', color: '#f97316' },
  { threshold: 65, level: 'CRITICAL', color: '#ef4444' },
];

/**
 * Calculate risk score for a session
 * @param {Object} sessionContext - Session data including events
 * @returns {Object} { score, level, breakdown }
 */
function calculateRiskScore(sessionContext) {
  let score = 0;
  const breakdown = [];
  const attackTypes = new Set();
  
  // Score each event
  for (const event of (sessionContext.events || [])) {
    if (event.attack_type && SCORE_WEIGHTS[event.attack_type]) {
      const points = SCORE_WEIGHTS[event.attack_type];
      score += points;
      attackTypes.add(event.attack_type);
      breakdown.push({
        reason: event.attack_type,
        points,
        timestamp: event.timestamp,
        path: event.path
      });
    }
  }
  
  // Behavioral modifiers
  const requestCount = sessionContext.request_count || 0;
  const durationMs = (sessionContext.last_seen || 0) - (sessionContext.first_seen || 0);
  const durationMin = durationMs / 60000;
  
  // High request rate
  if (durationMin > 0 && (requestCount / durationMin) > 60) {
    score += SCORE_WEIGHTS.HIGH_REQUEST_RATE;
    breakdown.push({ reason: 'HIGH_REQUEST_RATE', points: SCORE_WEIGHTS.HIGH_REQUEST_RATE });
  }
  
  // Multiple attack types used
  if (attackTypes.size > 2) {
    score += SCORE_WEIGHTS.MULTIPLE_ATTACK_TYPES;
    breakdown.push({ reason: 'MULTIPLE_ATTACK_TYPES', points: SCORE_WEIGHTS.MULTIPLE_ATTACK_TYPES });
  }
  
  // Bot user agent
  if (sessionContext.is_bot) {
    score += SCORE_WEIGHTS.BOT_USER_AGENT;
    breakdown.push({ reason: 'BOT_USER_AGENT', points: SCORE_WEIGHTS.BOT_USER_AGENT });
  }
  
  // Cap at 100
  score = Math.min(100, score);
  
  // Determine level
  let level = RISK_LEVELS[0];
  for (const rl of RISK_LEVELS) {
    if (score >= rl.threshold) level = rl;
  }
  
  return {
    score,
    level: level.level,
    color: level.color,
    breakdown
  };
}

/**
 * Quick score from single event (used during live event processing)
 */
function scoreEvent(attackType) {
  return SCORE_WEIGHTS[attackType] || 0;
}

module.exports = { calculateRiskScore, scoreEvent, RISK_LEVELS };