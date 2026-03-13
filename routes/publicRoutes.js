const express = require('express');
const router = express.Router();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const config = require('../config/config');

// Multer — accept file uploads (we log them, don't execute them)
const upload = multer({
  dest: path.join(config.paths.evidence, 'uploads'),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Accept everything — we want to log what attackers upload
    cb(null, true);
  }
});

// ── Serve Static Files ──────────────────────────────────────────────
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

router.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

router.get('/upload', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/upload.html'));
});



// ── Fake Authentication API ─────────────────────────────────────────
/**
 * Login endpoint
 * Looks real, acts real, but always fails (or succeeds with fake session)
 * Brute force will be logged by stealth middleware
 */
router.post('/api/auth/login', express.json(), (req, res) => {
  const { username, password } = req.body || {};
  
  // Simulate processing delay (realistic)
  const delay = 200 + Math.floor(Math.random() * 300);
  
  setTimeout(() => {
    // Always fail — but with realistic error messages
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request format',
        code: 'VALIDATION_ERROR'
      });
    }
    
    // For SQL injection attempts, return a fake SQL error (looks real!)
    const sqlPatterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'DROP'];
    const hasSQLi = sqlPatterns.some(p => 
      (username || '').toUpperCase().includes(p.toUpperCase()) ||
      (password || '').toUpperCase().includes(p.toUpperCase())
    );
    
    if (hasSQLi) {
      // Fake database error — looks exactly like a real MySQLerror
      return res.status(500).json({
        success: false,
        error: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1",
        code: 'DB_ERROR',
        errno: 1064
      });
    }
    
    // Normal fail
    res.status(401).json({
      success: false,
      error: 'Invalid username or password',
      code: 'AUTH_FAILED',
      remaining_attempts: Math.floor(Math.random() * 5) + 1
    });
  }, delay);
});

// ── Fake Register API ───────────────────────────────────────────────
router.post('/api/auth/register', express.json(), (req, res) => {
  const { username, email, password } = req.body || {};
  
  setTimeout(() => {
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'All fields are required'
      });
    }
    
    // Fake success with a fake user object
    res.status(201).json({
      success: true,
      message: 'Account created. Please check your email to verify.',
      user: {
        id: Math.floor(Math.random() * 9999) + 1000,
        username,
        email,
        created_at: new Date().toISOString()
      }
    });
  }, 300);
});

// ── Fake File Upload API ────────────────────────────────────────────
router.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'No file provided'
    });
  }
  
  // Log the upload metadata (stealth middleware already logged the request)
  // File is stored in evidence/uploads — we can examine what attackers upload
  
  // Fake success response
  res.json({
    success: true,
    message: 'File uploaded successfully',
    file: {
      id: require('uuid').v4(),
      name: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      url: `/storage/${req.file.filename}`,
      uploaded_at: new Date().toISOString()
    }
  });
});

// ── Fake API Endpoints ──────────────────────────────────────────────
router.get('/api/users', (req, res) => {
  // Fake user data — looks like a real API
  res.json({
    success: true,
    data: [
      { id: 1, name: 'Sarah Mitchell', role: 'Admin', email: 'sarah.m@techvault.io', last_login: '2024-01-15T09:32:00Z' },
      { id: 2, name: 'James Thornton', role: 'Manager', email: 'j.thornton@techvault.io', last_login: '2024-01-15T11:15:00Z' },
      { id: 3, name: 'Emily Chen', role: 'Analyst', email: 'e.chen@techvault.io', last_login: '2024-01-14T16:45:00Z' },
    ],
    total: 47,
    page: 1,
    per_page: 20
  });
});

router.get('/api/products', (req, res) => {
  res.json({
    success: true,
    data: [
      { id: 'P001', name: 'TechVault Pro', price: 299.99, sku: 'TV-PRO-001', stock: 142 },
      { id: 'P002', name: 'TechVault Enterprise', price: 999.99, sku: 'TV-ENT-001', stock: 38 },
      { id: 'P003', name: 'TechVault Starter', price: 49.99, sku: 'TV-STR-001', stock: 500 },
    ]
  });
});

router.get('/api/config', (req, res) => {
  // Fake config endpoint — lures attackers looking for exposed configs
  res.json({
    app: 'TechVault Solutions',
    version: '4.2.1',
    environment: 'production',
    features: {
      analytics: true,
      reporting: true,
      api_access: true
    }
    // Intentionally no real secrets here
  });
});

// Fake search endpoint — good SQLi target
router.get('/api/search', (req, res) => {
  const { q } = req.query;
  
  // Simulate search with fake results
  res.json({
    success: true,
    query: q || '',
    results: [
      { title: 'TechVault Documentation', url: '/docs/getting-started' },
      { title: 'API Reference Guide', url: '/docs/api' },
    ],
    total: 2
  });
});

// ── Fake Admin Panel (decoy) ────────────────────────────────────────
router.get('/admin', (req, res) => {
  // A decoy admin login that looks real but isn't the real admin
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

router.post('/admin/login', express.json(), (req, res) => {
  // Always fail with realistic message — stealth logs all attempts
  setTimeout(() => {
    res.status(403).json({
      success: false,
      error: 'Access denied',
      message: 'Invalid credentials or insufficient permissions'
    });
  }, 500 + Math.random() * 500);
});

// ── Catch-all for undefined routes ─────────────────────────────────
router.get('*', (req, res) => {
  // Return a realistic 404
  res.status(404).sendFile(path.join(__dirname, '../public/index.html'));
});

module.exports = router;