'use strict';
const jwt    = require('jsonwebtoken');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Verify JWT — no DB call. User profile is embedded in the JWT payload.
 * This makes auth completely stateless and resilient to DB issues.
 */
async function requireAuth(req, res, next) {
  try {
    const token = extractBearerToken(req) || req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }

    let payload;
    try {
      payload = jwt.verify(token, config.jwt.accessSecret);
    } catch (err) {
      const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
      return res.status(401).json({ error: 'Invalid or expired token', code });
    }

    // Attach user from JWT payload — no DB roundtrip needed
    req.user = {
      id:        payload.sub,
      email:     payload.email,
      name:      payload.name   || null,
      avatar:    payload.avatar || null,
      role:      payload.role   || 'USER',
      plan:      payload.plan   || 'FREE',
      trialUsed: payload.trialUsed || 0,
      trialMax:  payload.trialMax  || 10,
    };
    req.requestId = req.headers['x-request-id'] || payload.jti;

    next();
  } catch (err) {
    logger.error('Auth middleware error', { error: err.message });
    res.status(500).json({ error: 'Authentication error' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions', required: roles });
    }
    next();
  };
}

function requirePlan(...plans) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!plans.includes(req.user.plan)) {
      return res.status(402).json({ error: 'Plan upgrade required', current: req.user.plan, required: plans });
    }
    next();
  };
}

async function optionalAuth(req, res, next) {
  try {
    const token = extractBearerToken(req) || req.cookies?.access_token;
    if (!token) return next();
    const payload = jwt.verify(token, config.jwt.accessSecret);
    req.user = {
      id: payload.sub, email: payload.email, name: payload.name || null,
      role: payload.role || 'USER', plan: payload.plan || 'FREE',
      trialUsed: payload.trialUsed || 0, trialMax: payload.trialMax || 10,
    };
  } catch (_) { /* ignore */ }
  next();
}

function extractBearerToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

module.exports = { requireAuth, requireRole, requirePlan, optionalAuth };
