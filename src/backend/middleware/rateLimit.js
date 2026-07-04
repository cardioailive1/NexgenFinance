'use strict';
const rateLimit = require('express-rate-limit');
const logger    = require('../utils/logger');
const auditService = require('../services/auditService');

/**
 * Factory for rate limiters with audit logging on breach
 */
function createLimiter({ windowMs, max, message, name }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders:   false,
    keyGenerator: (req) => req.user?.id || req.ip,
    handler: async (req, res) => {
      logger.warn('Rate limit exceeded', {
        limiter:   name,
        userId:    req.user?.id || null,
        ip:        req.ip,
        path:      req.path,
        requestId: req.requestId,
      });

      await auditService.log({
        userId:    req.user?.id || null,
        action:    'RATE_LIMIT_HIT',
        resource:  req.path,
        outcome:   'blocked',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        requestId: req.requestId,
        details:   { limiter: name },
      });

      res.status(429).json({
        error:    message || 'Too many requests. Please slow down.',
        code:     'RATE_LIMITED',
        retryAfter: Math.ceil(windowMs / 1000),
      });
    },
    skip: (req) => req.user?.role === 'SUPER_ADMIN',
  });
}

// ── Limiters ──────────────────────────────────────────────────────────────────

// Global — all endpoints
const globalLimiter = createLimiter({
  name:      'global',
  windowMs:  60_000,   // 1 min
  max:       300,
  message:   'Too many requests from this IP.',
});

// Auth endpoints — prevent brute force
const authLimiter = createLimiter({
  name:      'auth',
  windowMs:  15 * 60_000, // 15 min
  max:       20,
  message:   'Too many authentication attempts. Wait 15 minutes.',
});

// Report generation — expensive AI calls
const reportLimiter = createLimiter({
  name:      'reports',
  windowMs:  60_000,  // 1 min
  max:       10,
  message:   'Report generation rate limit reached. Wait 1 minute.',
});

// API key endpoints
const apiKeyLimiter = createLimiter({
  name:      'api_keys',
  windowMs:  60 * 60_000, // 1 hour
  max:       50,
  message:   'API key operation rate limit reached.',
});

// Privacy / GDPR endpoints — prevent abuse
const privacyLimiter = createLimiter({
  name:      'privacy',
  windowMs:  60 * 60_000, // 1 hour
  max:       5,
  message:   'Data request rate limit reached. Max 5 per hour.',
});

module.exports = {
  globalLimiter,
  authLimiter,
  reportLimiter,
  apiKeyLimiter,
  privacyLimiter,
};
