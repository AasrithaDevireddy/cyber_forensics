
// SQL Injection patterns
const SQL_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
  /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
  /((\%27)|(\'))union/i,
  /exec(\s|\+)+(s|x)p\w+/i,
  /select.+from/i,
  /insert.+into/i,
  /delete.+from/i,
  /drop.+table/i,
  /update.+set/i,
  /union.+select/i,
  /or.+1\s*=\s*1/i,
  /and.+1\s*=\s*1/i,
  /sleep\s*\(/i,
  /benchmark\s*\(/i,
  /load_file\s*\(/i,
  /into\s+outfile/i,
  /information_schema/i,
  /xp_cmdshell/i,
  /waitfor\s+delay/i,
  /;\s*drop/i,
  /'\s*or\s*'/i,
  /1\s*or\s*1/i,
  /admin'\s*--/i,
];

// XSS patterns
const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/i,
  /<script[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=/i,          // onclick=, onerror=, etc.
  /<iframe/i,
  /<object/i,
  /<embed/i,
  /document\.cookie/i,
  /document\.write/i,
  /eval\s*\(/i,
  /alert\s*\(/i,
  /confirm\s*\(/i,
  /prompt\s*\(/i,
  /<img[^>]+onerror/i,
  /src\s*=\s*javascript/i,
  /\%3Cscript/i,
  /&lt;script/i,
  /&#60;script/i,
];

// Command injection patterns
const CMD_PATTERNS = [
  /;\s*(ls|cat|pwd|whoami|id|uname|ifconfig|ps|kill|rm|mv|cp)\s/i,
  /\|\s*(ls|cat|pwd|whoami|id|uname|ifconfig)\s/i,
  /`[^`]+`/,             // Backtick execution
  /\$\([^)]+\)/,         // Command substitution
  /&&\s*(ls|cat|rm|wget|curl)/i,
  /\|\|\s*(ls|cat|rm|wget|curl)/i,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/proc\/self/i,
  /wget\s+http/i,
  /curl\s+-[a-z]/i,
  /nc\s+-[a-z]/i,        // netcat
  /bash\s+-[ic]/i,
  /python[23]?\s+-c/i,
  /perl\s+-e/i,
];

// Path traversal patterns
const PATH_PATTERNS = [
  /\.\.\//,
  /\.\.%2f/i,
  /\.\.%5c/i,
  /%252e%252e%252f/i,
  /\.\.\\/,
  /\/\.\.$/,
  /\%2e\%2e\%2f/i,
  /\.\.\/\.\.\/\.\.\//,
  /etc\/passwd/i,
  /windows\/system32/i,
  /boot\.ini/i,
];

// Known scanner/bot user agents
const BOT_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /masscan/i,
  /python-requests/i,
  /curl\//i,
  /wget\//i,
  /burpsuite/i,
  /dirbuster/i,
  /gobuster/i,
  /wfuzz/i,
  /hydra/i,
  /metasploit/i,
  /nessus/i,
  /openvas/i,
  /acunetix/i,
  /qualys/i,
  /nuclei/i,
  /zgrab/i,
  /shodan/i,
  /censys/i,
  /masscan/i,
  /zgrab/i,
];

// XML injection / XXE patterns  
const XXE_PATTERNS = [
  /<!ENTITY/i,
  /<!DOCTYPE[^>]+\[/i,
  /SYSTEM\s+"(file|http|ftp|php|data):/i,
  /PUBLIC\s+"[^"]*"\s+"[^"]*"/i,
];

// SSRF patterns (in parameter values)
const SSRF_PATTERNS = [
  /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i,
  /https?:\/\/169\.254\./i,     // AWS metadata
  /https?:\/\/10\.\d+\.\d+\.\d+/i,
  /https?:\/\/192\.168\.\d+\.\d+/i,
  /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i,
  /file:\/\//i,
  /dict:\/\//i,
  /gopher:\/\//i,
  /ftp:\/\//i,
];

/**
 * Scan a string value for attack patterns
 * Returns array of detected attacks
 */
function scanValue(value) {
  if (!value || typeof value !== 'string') return [];
  
  const detections = [];
  
  if (SQL_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'SQL_INJECTION', value });
  }
  
  if (XSS_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'XSS', value });
  }
  
  if (CMD_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'COMMAND_INJECTION', value });
  }
  
  if (PATH_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'PATH_TRAVERSAL', value });
  }
  
  if (XXE_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'XXEI', value });
  }
  
  if (SSRF_PATTERNS.some(p => p.test(value))) {
    detections.push({ type: 'SSRF', value });
  }
  
  return detections;
}

/**
 * Recursively scan object for attack patterns
 */
function scanObject(obj, depth = 0) {
  if (depth > 5) return []; // Prevent deep recursion
  
  const detections = [];
  
  if (typeof obj === 'string') {
    detections.push(...scanValue(obj));
  } else if (typeof obj === 'object' && obj !== null) {
    for (const [key, val] of Object.entries(obj)) {
      // Check key itself
      detections.push(...scanValue(key));
      // Check value
      if (typeof val === 'string') {
        detections.push(...scanValue(val));
      } else if (typeof val === 'object') {
        detections.push(...scanObject(val, depth + 1));
      }
    }
  }
  
  return detections;
}

/**
 * Detect bot user agents
 */
function detectBot(userAgent) {
  if (!userAgent) return false;
  return BOT_UA_PATTERNS.some(p => p.test(userAgent));
}

/**
 * Main analysis function — analyzes a complete request
 */
function analyzeRequest(req) {
  const detections = [];
  
  // Scan query parameters
  if (req.query) {
    const queryDetections = scanObject(req.query);
    detections.push(...queryDetections);
  }
  
  // Scan request body
  if (req.body) {
    const bodyDetections = scanObject(req.body);
    detections.push(...bodyDetections);
  }
  
  // Scan URL path
  const pathDetections = scanValue(decodeURIComponent(req.path || ''));
  detections.push(...pathDetections);
  
  // Scan headers (selective — only user-controlled ones)
  const headerTargets = [
    'x-forwarded-for', 'x-real-ip', 'referer', 'user-agent',
    'x-custom-header', 'accept', 'accept-language'
  ];
  
  for (const header of headerTargets) {
    const value = req.headers[header];
    if (value) detections.push(...scanValue(value));
  }
  
  // Deduplicate by type
  const seen = new Set();
  const unique = detections.filter(d => {
    if (seen.has(d.type)) return false;
    seen.add(d.type);
    return true;
  });
  
  return {
    isAttack: unique.length > 0,
    isBot: detectBot(req.headers['user-agent']),
    detections: unique,
    primaryAttack: unique.length > 0 ? unique[0].type : null,
  };
}

module.exports = { analyzeRequest, detectBot, scanValue };