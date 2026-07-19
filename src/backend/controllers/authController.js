'use strict';
const jwt         = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const prisma      = require('../config/prisma');
const config      = require('../config');
const logger      = require('../utils/logger');
const auditService = require('../services/auditService');
const { randomToken } = require('../services/encryptionService');

const ACCESS_TTL_MS  = parseDuration(config.jwt.accessTtl);
const REFRESH_TTL_MS = parseDuration(config.jwt.refreshTtl);

// ── Token helpers ─────────────────────────────────────────────────────────────

function issueTokens(user) {
  const jti = uuidv4();

  const accessToken = jwt.sign(
    {
      sub:        user.id,
      email:      user.email,
      name:       user.name || null,
      avatar:     user.avatar || null,
      role:       user.role,
      plan:       user.plan,
      trialUsed:  user.trialUsed,
      trialMax:   user.trialMax,
      jti,
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessTtl }
  );

  const refreshToken = randomToken(48);

  return {
    accessToken,
    refreshToken,
    accessExpiry:  new Date(Date.now() + ACCESS_TTL_MS),
    refreshExpiry: new Date(Date.now() + REFRESH_TTL_MS),
  };
}

async function createSession(user, tokens, req) {
  return prisma.session.create({
    data: {
      userId:       user.id,
      accessToken:  tokens.accessToken,
      refreshToken: tokens.refreshToken,
      accessExpiry: tokens.accessExpiry,
      refreshExpiry: tokens.refreshExpiry,
      ipAddress:    req.ip,
      userAgent:    req.headers['user-agent'] || null,
    },
  });
}

function setCookies(res, tokens) {
  const cookieOpts = {
    httpOnly: true,
    secure:   config.isProd(),
    sameSite: 'lax',
    path:     '/',
  };
  res.cookie('access_token',  tokens.accessToken,  { ...cookieOpts, maxAge: ACCESS_TTL_MS });
  res.cookie('refresh_token', tokens.refreshToken, { ...cookieOpts, maxAge: REFRESH_TTL_MS });
}

// ── Controllers ───────────────────────────────────────────────────────────────

/**
 * POST /api/auth/refresh
 * Exchange a valid refresh token for a new access token.
 */
async function refreshToken(req, res) {
  try {
    const token = req.body.refreshToken || req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ error: 'Refresh token required' });

    const session = await prisma.session.findUnique({
      where:   { refreshToken: token },
      include: { user: true },
    });

    if (!session || session.isRevoked) {
      return res.status(401).json({ error: 'Invalid refresh token', code: 'INVALID_REFRESH' });
    }
    if (new Date() > session.refreshExpiry) {
      await prisma.session.update({ where: { id: session.id }, data: { isRevoked: true, revokedReason: 'expired' } });
      return res.status(401).json({ error: 'Refresh token expired', code: 'REFRESH_EXPIRED' });
    }

    const user = session.user;
    if (!user.isActive || user.deletedAt) {
      return res.status(403).json({ error: 'Account disabled' });
    }

    // Rotate — revoke old, issue new
    const newTokens = issueTokens(user);
    await prisma.session.update({
      where: { id: session.id },
      data:  {
        accessToken:  newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        accessExpiry: newTokens.accessExpiry,
        refreshExpiry: newTokens.refreshExpiry,
        updatedAt:    new Date(),
      },
    });

    setCookies(res, newTokens);

    res.json({
      accessToken: newTokens.accessToken,
      expiresAt:   newTokens.accessExpiry,
    });
  } catch (err) {
    logger.error('Token refresh failed', { error: err.message });
    res.status(500).json({ error: 'Token refresh failed' });
  }
}

/**
 * POST /api/auth/logout
 */
async function logout(req, res) {
  try {
    if (req.session) {
      await prisma.session.update({
        where: { id: req.session.id },
        data:  { isRevoked: true, revokedAt: new Date(), revokedReason: 'logout' },
      });
    }

    await auditService.log({
      userId:    req.user?.id,
      action:    'LOGOUT',
      outcome:   'success',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      requestId: req.requestId,
    });

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Logout error', { error: err.message });
    res.status(500).json({ error: 'Logout failed' });
  }
}

/**
 * POST /api/auth/logout/all  — revoke all sessions
 */
async function logoutAll(req, res) {
  try {
    await prisma.session.updateMany({
      where: { userId: req.user.id, isRevoked: false },
      data:  { isRevoked: true, revokedAt: new Date(), revokedReason: 'logout_all' },
    });

    await auditService.log({
      userId:    req.user.id,
      action:    'LOGOUT',
      resource:  'all_sessions',
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
    });

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.json({ message: 'All sessions revoked' });
  } catch (err) {
    logger.error('Logout all error', { error: err.message });
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
}

/**
 * GET /api/auth/me
 */
async function me(req, res) {
  const { id, email, name, avatar, role, plan, trialUsed, trialMax, reportsTotal, createdAt } = req.user;
  res.json({ id, email, name, avatar, role, plan, trialUsed, trialMax, reportsTotal, createdAt });
}

/**
 * OAuth2 callback success handler — called after passport.authenticate()
 */
async function oauthCallback(req, res) {
  try {
    if (!req.user) {
      logger.warn('OAuth callback: no user on request');
      return res.redirect(`${config.frontend.url}/?error=oauth_failed`);
    }

    const tokens = issueTokens(req.user);

    // Session creation is best-effort — auth works via JWT even if this fails
    try {
      await createSession(req.user, tokens, req);
    } catch (sessionErr) {
      logger.error('Session creation failed (non-fatal)', { error: sessionErr.message, userId: req.user.id });
    }

    setCookies(res, tokens);
    logger.info('OAuth login success, redirecting to app', { userId: req.user.id });
    res.redirect(`${config.frontend.url}/`);
  } catch (err) {
    logger.error('OAuth callback error', { error: err.message, stack: err.stack });
    res.redirect(`${config.frontend.url}/?error=server_error`);
  }
}

function parseDuration(str) {
  const n = parseInt(str, 10);
  if (str.endsWith('d'))  return n * 86_400_000;
  if (str.endsWith('h'))  return n * 3_600_000;
  if (str.endsWith('m'))  return n * 60_000;
  if (str.endsWith('s'))  return n * 1_000;
  return n;
}

module.exports = { refreshToken, logout, logoutAll, me, oauthCallback, issueTokens, createSession, setCookies };
