'use strict';
const helmet      = require('helmet');
const cors        = require('cors');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const config      = require('../config');
const logger      = require('../utils/logger');

/**
 * Helmet — comprehensive HTTP security headers
 * SOC2 CC6.6 — Restricts access to information assets
 */
const helmetMiddleware = helmet({
  contentSecurityPolicy: false, // Disabled — inline onclick handlers in SPA need unsafe-inline
  hsts: config.isProd()
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  referrerPolicy:           { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
});

/**
 * CORS — whitelist configured origins
 */
const corsMiddleware = cors({
  origin(origin, cb) {
    // Allow non-browser requests (Postman, server-to-server) in dev
    if (!origin && config.isDev()) return cb(null, true);
    if (!origin || config.cors.origins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials:     true,
  allowedHeaders:  ['Content-Type', 'Authorization', 'X-Request-ID', 'X-API-Key'],
  exposedHeaders:  ['X-Request-ID', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  methods:         ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  maxAge:          600,
});

/**
 * Attach correlation request ID to every request (SOC2 traceability)
 */
function requestId(req, res, next) {
  const id = req.headers['x-request-id'] || uuidv4();
  req.requestId = id;
  res.setHeader('X-Request-ID', id);
  next();
}

/**
 * Structured access log (SOC2 CC7.2 — monitor system components)
 */
function accessLog(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[level]('HTTP', {
      method:    req.method,
      path:      req.path,
      status:    res.statusCode,
      ms,
      ip:        req.ip,
      requestId: req.requestId,
      userId:    req.user?.id || null,
    });
  });
  next();
}

/**
 * Compliance headers — GDPR Article 25 (privacy by design)
 */
function complianceHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options',    'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('X-XSS-Protection',          '1; mode=block');
  res.setHeader('Permissions-Policy',        'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control',             'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma',                    'no-cache');
  res.setHeader('X-Powered-By-Override',     'NexGen Finance');
  // Remove Express fingerprint
  res.removeHeader('X-Powered-By');
  next();
}

/**
 * Max request body size guard
 */
function bodySizeGuard(limit = '1mb') {
  return (req, res, next) => {
    const len = parseInt(req.headers['content-length'] || '0', 10);
    const bytes = parseSizeLimit(limit);
    if (len > bytes) {
      return res.status(413).json({ error: 'Request body too large' });
    }
    next();
  };
}

function parseSizeLimit(limit) {
  const n = parseInt(limit, 10);
  if (limit.endsWith('mb')) return n * 1024 * 1024;
  if (limit.endsWith('kb')) return n * 1024;
  return n;
}

module.exports = {
  helmetMiddleware,
  corsMiddleware,
  requestId,
  accessLog,
  complianceHeaders,
  bodySizeGuard,
  compression: compression({ level: 6, threshold: 1024 }),
};
