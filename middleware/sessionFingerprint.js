const crypto = require('crypto');
const geoip = require('geoip-lite');
const useragent = require('useragent');

/**
 * Normalize IP address (handle IPv6-mapped IPv4)
 */
function normalizeIP(ip) {
  if (!ip) return '0.0.0.0';
  // Handle IPv6-mapped IPv4 (::ffff:192.168.1.1)
  const ipv4Match = ip.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
  if (ipv4Match) return ipv4Match[1];
  return ip;
}

/**
 * Get real IP from request (handles proxies)
 */
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // Take first IP in chain (original client)
    return forwarded.split(',')[0].trim();
  }
  return req.headers['x-real-ip'] || req.connection?.remoteAddress || req.ip || '0.0.0.0';
}


function createFingerprint(req) {
  const rawIP = getRealIP(req);
  const ip = normalizeIP(rawIP);
  const userAgent = req.headers['user-agent'] || 'unknown';
  const acceptLang = req.headers['accept-language'] || '';
  const acceptEnc = req.headers['accept-encoding'] || '';
  
  // Fingerprint components
  const fingerprintData = `${ip}|${userAgent}|${acceptLang}|${acceptEnc}`;
  
  const fingerprint = crypto
    .createHash('sha256')
    .update(fingerprintData)
    .digest('hex');
  
  // Session ID is first 32 chars of fingerprint (still unique enough)
  const sessionId = fingerprint.substring(0, 32);
  
  // Geo lookup
  const geo = geoip.lookup(ip) || {};
  
  // Parse user agent
  let uaParsed = {};
  try {
    const uaObj = useragent.parse(userAgent);
    uaParsed = {
      browser: uaObj.family,
      browserVersion: `${uaObj.major}.${uaObj.minor}`,
      os: uaObj.os.family,
      osVersion: `${uaObj.os.major}`,
      device: uaObj.device.family,
    };
  } catch (e) {
    uaParsed = { browser: 'Unknown', os: 'Unknown' };
  }
  
  return {
    sessionId,
    fingerprint,
    ip,
    rawIP,
    userAgent,
    uaParsed,
    geo: {
      country: geo.country || null,
      city: geo.city || null,
      region: geo.region || null,
      lat: geo.ll ? geo.ll[0] : null,
      lon: geo.ll ? geo.ll[1] : null,
    },
    timestamp: Date.now(),
  };
}

module.exports = { createFingerprint, getRealIP, normalizeIP };