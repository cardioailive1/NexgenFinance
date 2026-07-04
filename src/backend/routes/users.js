'use strict';
const express  = require('express');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const router   = express.Router();
const prisma   = require('../config/prisma');
const { requireAuth, requireRole } = require('../middleware/auth');
const { apiKeyLimiter }  = require('../middleware/rateLimit');
const auditService = require('../services/auditService');
const { randomToken, hash } = require('../services/encryptionService');
const logger   = require('../utils/logger');

router.use(requireAuth);

// ── Profile ───────────────────────────────────────────────────────────────────

router.get('/profile', async (req, res) => {
  const user = await prisma.user.findUnique({
    where:  { id: req.user.id },
    select: { id: true, email: true, name: true, avatar: true, role: true, plan: true,
              trialUsed: true, trialMax: true, reportsTotal: true, consentGdpr: true,
              marketingOptIn: true, isEmailVerified: true, isMfaEnabled: true,
              createdAt: true, lastLoginAt: true },
  });
  res.json(user);
});

router.patch('/profile', async (req, res) => {
  const allowed = ['name', 'marketingOptIn'];
  const data = {};
  allowed.forEach((k) => { if (req.body[k] !== undefined) data[k] = req.body[k]; });

  const updated = await prisma.user.update({ where: { id: req.user.id }, data });
  await auditService.log({ userId: req.user.id, action: 'USER_UPDATE', outcome: 'success', ipAddress: req.ip, requestId: req.requestId });
  res.json({ message: 'Profile updated', name: updated.name });
});

// ── Sessions ──────────────────────────────────────────────────────────────────

router.get('/sessions', async (req, res) => {
  const sessions = await prisma.session.findMany({
    where:   { userId: req.user.id, isRevoked: false, refreshExpiry: { gt: new Date() } },
    select:  { id: true, ipAddress: true, userAgent: true, createdAt: true, updatedAt: true },
    orderBy: { updatedAt: 'desc' },
  });
  res.json(sessions);
});

router.delete('/sessions/:id', async (req, res) => {
  const session = await prisma.session.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!session) return res.status(404).json({ error: 'Session not found' });

  await prisma.session.update({
    where: { id: session.id },
    data:  { isRevoked: true, revokedAt: new Date(), revokedReason: 'user_revoked' },
  });
  res.json({ message: 'Session revoked' });
});

// ── API Keys ──────────────────────────────────────────────────────────────────

router.get('/api-keys', apiKeyLimiter, async (req, res) => {
  const keys = await prisma.apiKey.findMany({
    where:   { userId: req.user.id, isRevoked: false },
    select:  { id: true, name: true, keyPrefix: true, scopes: true, lastUsedAt: true, expiresAt: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
  });
  res.json(keys);
});

router.post('/api-keys', apiKeyLimiter, async (req, res) => {
  const { name, scopes = ['reports:read', 'reports:write'], expiresInDays = 365 } = req.body;
  if (!name) return res.status(400).json({ error: 'Key name required' });

  const rawKey  = `nxg_${randomToken(32)}`;
  const keyHash = await bcrypt.hash(rawKey, 12);
  const expiry  = new Date(Date.now() + expiresInDays * 86_400_000);

  const apiKey = await prisma.apiKey.create({
    data: {
      userId:    req.user.id,
      name,
      keyHash,
      keyPrefix: rawKey.slice(0, 12),
      scopes,
      expiresAt: expiry,
    },
  });

  await auditService.log({
    userId: req.user.id, action: 'API_KEY_CREATE', resource: `api_key:${apiKey.id}`,
    outcome: 'success', ipAddress: req.ip, requestId: req.requestId,
  });

  // Return raw key ONCE — never stored in plaintext
  res.status(201).json({
    id:        apiKey.id,
    name,
    key:       rawKey,
    keyPrefix: apiKey.keyPrefix,
    scopes,
    expiresAt: expiry,
    warning:   'Store this key securely — it will not be shown again.',
  });
});

router.delete('/api-keys/:id', apiKeyLimiter, async (req, res) => {
  const key = await prisma.apiKey.findFirst({ where: { id: req.params.id, userId: req.user.id } });
  if (!key) return res.status(404).json({ error: 'API key not found' });

  await prisma.apiKey.update({ where: { id: key.id }, data: { isRevoked: true, revokedAt: new Date() } });
  await auditService.log({
    userId: req.user.id, action: 'API_KEY_REVOKE', resource: `api_key:${key.id}`,
    outcome: 'success', ipAddress: req.ip, requestId: req.requestId,
  });
  res.json({ message: 'API key revoked' });
});

// ── Admin ─────────────────────────────────────────────────────────────────────

router.get('/all', requireRole('ADMIN', 'SUPER_ADMIN'), async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const users = await prisma.user.findMany({
    where:   { deletedAt: null },
    select:  { id: true, email: true, name: true, role: true, plan: true, trialUsed: true, reportsTotal: true, isActive: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
    skip:    (parseInt(page) - 1) * parseInt(limit),
    take:    parseInt(limit),
  });
  res.json(users);
});

module.exports = router;
