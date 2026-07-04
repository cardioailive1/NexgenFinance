'use strict';
const jwt    = require('jsonwebtoken');
const prisma = require('../config/prisma');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Verify JWT access token from Authorization header or cookie.
 * Attaches req.user (User model) and req.session (Session model).
 */
async function requireAuth(req, res, next) {
  try {
    const token =
      extractBearerToken(req) ||
      req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }

    // Verify signature & expiry
    let payload;
    try {
      payload = jwt.verify(token, config.jwt.accessSecret);
    } catch (err) {
      const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID';
      return res.status(401).json({ error: 'Invalid or expired token', code });
    }

    // Validate session still exists and is not revoked
    const session = await prisma.session.findUnique({
      where:   { accessToken: token },
      include: { user: true },
    });

    if (!session || session.isRevoked) {
      return res.status(401).json({ error: 'Session revoked', code: 'SESSION_REVOKED' });
    }
    if (new Date() > session.accessExpiry) {
      return res.status(401).json({ error: 'Session expired', code: 'TOKEN_EXPIRED' });
    }

    const user = session.user;
    if (!user.isActive || user.deletedAt) {
      return res.status(403).json({ error: 'Account disabled', code: 'ACCOUNT_DISABLED' });
    }

    req.user    = user;
    req.session = session;
    req.requestId = req.headers['x-request-id'] || payload.jti;

    next();
  } catch (err) {
    logger.error('Auth middleware error', { error: err.message });
    res.status(500).json({ error: 'Authentication error' });
  }
}

/**
 * Role guard factory — use after requireAuth
 * e.g. requireRole('ADMIN', 'SUPER_ADMIN')
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions', required: roles });
    }
    next();
  };
}

/**
 * Plan guard factory — use after requireAuth
 * e.g. requirePlan('PRO', 'ENTERPRISE')
 */
function requirePlan(...plans) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!plans.includes(req.user.plan)) {
      return res.status(402).json({
        error:    'Plan upgrade required',
        current:  req.user.plan,
        required: plans,
        upgradeUrl: '/billing/upgrade',
      });
    }
    next();
  };
}

/**
 * Soft auth — attaches user if token present but doesn't block
 */
async function optionalAuth(req, res, next) {
  try {
    const token = extractBearerToken(req) || req.cookies?.access_token;
    if (!token) return next();

    const payload = jwt.verify(token, config.jwt.accessSecret);
    const session = await prisma.session.findUnique({
      where:   { accessToken: token },
      include: { user: true },
    });
    if (session && !session.isRevoked && session.user?.isActive) {
      req.user    = session.user;
      req.session = session;
    }
  } catch (_) { /* ignore */ }
  next();
}

function extractBearerToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

module.exports = { requireAuth, requireRole, requirePlan, optionalAuth };
