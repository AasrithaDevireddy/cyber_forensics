/**
 * Central configuration loader
 * All environment variables validated here
 */
require('dotenv').config();

const config = {
  port: parseInt(process.env.PORT) || 3000,
  adminPort: parseInt(process.env.ADMIN_PORT) || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  admin: {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'changeme',
    secretPath: process.env.ADMIN_SECRET_PATH || 'x-vault-control',
    ipWhitelist: process.env.ADMIN_IP_WHITELIST 
      ? process.env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim())
      : [],
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret-change-this',
    expiresIn: process.env.JWT_EXPIRES_IN || '8h',
  },
  
  paths: {
    db: process.env.DB_PATH || './data/forensics.db',
    evidence: process.env.EVIDENCE_PATH || './data/evidence',
    reports: process.env.REPORTS_PATH || './reports',
  },
  
  evidenceKey: process.env.EVIDENCE_KEY || 'DefaultKey32CharsPleaseChange!!',
};

// Validate critical config
if (config.jwt.secret === 'fallback-secret-change-this' && config.nodeEnv === 'production') {
  console.error('[FATAL] JWT_SECRET not set in production mode. Exiting.');
  process.exit(1);
}

module.exports = config;