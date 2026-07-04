'use strict';
const { body, validationResult } = require('express-validator');
const prisma          = require('../config/prisma');
const config          = require('../config');
const logger          = require('../utils/logger');
const auditService    = require('../services/auditService');
const anthropicService = require('../services/anthropicService');
const { encrypt, decrypt, hash } = require('../services/encryptionService');

const MODULES = ['STATEMENTS', 'ACCOUNTING', 'AUDIT', 'MARKET', 'TRADING'];

// SEC requires 7-year retention for financial records
const RETENTION_YEARS = config.compliance.secRetentionYears;

// ── Validation ────────────────────────────────────────────────────────────────

const generateValidation = [
  body('module').isIn(MODULES).withMessage('Invalid module'),
  body('reportType').isString().trim().notEmpty().isLength({ max: 64 }),
  body('prompt').isString().trim().notEmpty().isLength({ min: 10, max: 20_000 }),
  body('inputData').optional().isObject(),
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function canGenerate(user) {
  if (user.plan === 'PRO' || user.plan === 'ENTERPRISE') return { ok: true };
  if (user.trialUsed >= user.trialMax) {
    return { ok: false, reason: 'Trial limit reached', code: 'TRIAL_EXHAUSTED' };
  }
  return { ok: true };
}

function retainUntil() {
  const d = new Date();
  d.setFullYear(d.getFullYear() + RETENTION_YEARS);
  return d;
}

// ── Controllers ───────────────────────────────────────────────────────────────

/**
 * POST /api/reports/generate
 */
async function generate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Validation failed', details: errors.array() });
  }

  const { module: mod, reportType, prompt, inputData } = req.body;
  const user = req.user;

  // Trial / plan gate
  const access = canGenerate(user);
  if (!access.ok) {
    return res.status(402).json({ error: access.reason, code: access.code });
  }

  let report;
  try {
    // Call Anthropic
    const { text, tokenCount, model } = await anthropicService.generateReport({ module: mod, prompt });

    // Encrypt and store (GDPR Article 32 — security of processing)
    const inputEnc  = encrypt(JSON.stringify(inputData || {}));
    const outputEnc = encrypt(text);
    const contentHash = hash(text);

    report = await prisma.$transaction(async (tx) => {
      // Create report record
      const r = await tx.report.create({
        data: {
          userId:      user.id,
          module:      mod,
          reportType,
          title:       `${mod} / ${reportType}`,
          inputDataEnc: inputEnc,
          outputEnc,
          contentHash,
          tokenCount,
          modelUsed:   model,
          retainUntil: retainUntil(),
        },
      });

      // Increment usage counters
      await tx.user.update({
        where: { id: user.id },
        data: {
          trialUsed:    user.plan === 'FREE' ? { increment: 1 } : undefined,
          reportsTotal: { increment: 1 },
        },
      });

      return r;
    });

    await auditService.log({
      userId:    user.id,
      action:    'REPORT_GENERATE',
      resource:  `report:${report.id}`,
      outcome:   'success',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      requestId: req.requestId,
      details:   { module: mod, reportType, tokenCount, model },
    });

    // Return decrypted output — never store plaintext in response log
    res.status(201).json({
      reportId:  report.id,
      module:    mod,
      reportType,
      output:    text,
      tokenCount,
      model,
      createdAt: report.createdAt,
      trialsRemaining: user.plan === 'FREE'
        ? Math.max(0, user.trialMax - user.trialUsed - 1)
        : null,
    });
  } catch (err) {
    logger.error('Report generation failed', { error: err.message, userId: user.id, mod });

    await auditService.log({
      userId:    user.id,
      action:    'REPORT_GENERATE',
      resource:  `module:${mod}`,
      outcome:   'failure',
      ipAddress: req.ip,
      requestId: req.requestId,
      details:   { error: err.message },
    });

    res.status(500).json({ error: 'Report generation failed. Please try again.' });
  }
}

/**
 * GET /api/reports
 */
async function list(req, res) {
  try {
    const { page = 1, limit = 20, module: mod } = req.query;
    const skip  = (parseInt(page) - 1) * parseInt(limit);
    const where = {
      userId:    req.user.id,
      deletedAt: null,
      ...(mod ? { module: mod } : {}),
    };

    const [reports, total] = await Promise.all([
      prisma.report.findMany({
        where,
        orderBy:  { createdAt: 'desc' },
        skip,
        take:     parseInt(limit),
        select:   { id: true, module: true, reportType: true, title: true, tokenCount: true, modelUsed: true, createdAt: true },
      }),
      prisma.report.count({ where }),
    ]);

    res.json({ reports, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
  } catch (err) {
    logger.error('Report list error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
}

/**
 * GET /api/reports/:id
 */
async function getOne(req, res) {
  try {
    const report = await prisma.report.findFirst({
      where: { id: req.params.id, userId: req.user.id, deletedAt: null },
    });

    if (!report) return res.status(404).json({ error: 'Report not found' });

    await auditService.log({
      userId:    req.user.id,
      action:    'REPORT_VIEW',
      resource:  `report:${report.id}`,
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
    });

    // Decrypt on read
    const output    = decrypt(report.outputEnc);
    const inputData = JSON.parse(decrypt(report.inputDataEnc) || '{}');

    // Tamper detection (SEC audit trail integrity)
    const expectedHash = hash(output);
    const tampered = expectedHash !== report.contentHash;
    if (tampered) {
      logger.warn('Report content hash mismatch — possible tampering', { reportId: report.id });
    }

    res.json({ ...report, output, inputData, outputEnc: undefined, inputDataEnc: undefined, tampered });
  } catch (err) {
    logger.error('Report fetch error', { error: err.message });
    res.status(500).json({ error: 'Failed to retrieve report' });
  }
}

/**
 * DELETE /api/reports/:id  (soft delete)
 */
async function remove(req, res) {
  try {
    const report = await prisma.report.findFirst({
      where: { id: req.params.id, userId: req.user.id, deletedAt: null },
    });
    if (!report) return res.status(404).json({ error: 'Report not found' });

    // Cannot delete within SEC retention window
    if (report.retainUntil > new Date()) {
      return res.status(403).json({
        error: `Report must be retained until ${report.retainUntil.toISOString()} per SEC compliance requirements.`,
        code:  'SEC_RETENTION',
      });
    }

    await prisma.report.update({
      where: { id: report.id },
      data:  { deletedAt: new Date() },
    });

    await auditService.log({
      userId:    req.user.id,
      action:    'REPORT_DELETE',
      resource:  `report:${report.id}`,
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
    });

    res.json({ message: 'Report deleted' });
  } catch (err) {
    logger.error('Report delete error', { error: err.message });
    res.status(500).json({ error: 'Failed to delete report' });
  }
}

module.exports = { generate, generateValidation, list, getOne, remove };
