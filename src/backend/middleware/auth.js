'use strict';
const jwt    = require('jsonwebtoken');
const prisma = require('../config/prisma');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Verify JWT access token — no DB session lookup required.
 * JWT signature + expiry is sufficient for stateless auth.
 * Sessions in DB are kept for audit/revocation only.
 */
async function requireAuth(req, res, next) {
  try {
    const token =
      extractBearerToken(req) ||
      req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }

    // Verify JWT signature and expiry
    let payload;
    try {
      payload = jwt.verify(token, config.jwt.accessSecret);
    } catch (err) {
      const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
      return res.status(401).json({ error: 'Invalid or expired token', code });
    }

    // Fetch user from DB
    const user = await prisma.user.findUnique({ where: { id: payload.sub } });

    if (!user) {
      return res.status(401).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
    }
    if (!user.isActive || user.deletedAt) {
      return res.status(403).json({ error: 'Account disabled', code: 'ACCOUNT_DISABLED' });
    }

    req.user      = user;
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
    const user    = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (user && user.isActive && !user.deletedAt) req.user = user;
  } catch (_) { /* ignore */ }
  next();
}

function extractBearerToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

module.exports = { requireAuth, requireRole, requirePlan, optionalAuth };
