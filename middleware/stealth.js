const { createFingerprint } = require('./sessionFingerprint');
const { analyzeRequest } = require('./attackDetector');
const { forensicBus } = require('../forensics/engine');

/**
 * Main stealth middleware
 * Wraps the response to capture status code, then emits forensic event
 */
function stealthMiddleware(req, res, next) {
  const startTime = Date.now();
  
  // Override res.end to capture response details
  // This is a standard Node.js pattern — completely transparent to the client
  const originalEnd = res.end.bind(res);
  
  res.end = function(chunk, encoding) {
    // Restore original
    res.end = originalEnd;
    
    // Call original first (response goes out immediately)
    const result = originalEnd(chunk, encoding);
    
    // AFTER response is sent, do our logging (zero impact on response time from attacker's view)
    const responseTime = Date.now() - startTime;
    
    // Skip logging for static assets (reduce noise)
    const staticExtensions = /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$/i;
    if (staticExtensions.test(req.path)) {
      return result;
    }
    
    // Fire and forget — fully async
    setImmediate(() => {
      try {
        const fingerprint = createFingerprint(req);
        const analysis = analyzeRequest(req);
        
        forensicBus.emit('event', {
          fingerprint,
          analysis,
          req: {
            method: req.method,
            path: req.path,
            query: req.query,
            headers: req.headers,
            body: req.body,
            ip: req.ip,
          },
          statusCode: res.statusCode,
          responseTime,
        });
      } catch (e) {
        // Silent failure — NEVER let monitoring errors surface
      }
    });
    
    return result;
  };
  
  next();
}

module.exports = stealthMiddleware;