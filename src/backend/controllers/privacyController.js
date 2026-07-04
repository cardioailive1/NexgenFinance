'use strict';
const prisma       = require('../config/prisma');
const config       = require('../config');
const logger       = require('../utils/logger');
const auditService = require('../services/auditService');
const { decrypt }  = require('../services/encryptionService');

/**
 * POST /api/privacy/consent
 * Record GDPR/CCPA consent (Article 7 — conditions for consent)
 */
async function recordConsent(req, res) {
  try {
    const { consentType, granted, version } = req.body;
    const allowedTypes = ['gdpr', 'ccpa', 'marketing', 'cookies'];

    if (!allowedTypes.includes(consentType)) {
      return res.status(400).json({ error: 'Invalid consent type' });
    }

    await prisma.$transaction([
      prisma.consentRecord.create({
        data: {
          userId:      req.user.id,
          consentType,
          granted:     Boolean(granted),
          ipAddress:   req.ip,
          userAgent:   req.headers['user-agent'],
          version:     version || config.compliance.policyVersion,
        },
      }),
      prisma.user.update({
        where: { id: req.user.id },
        data: {
          consentGdpr:   consentType === 'gdpr'      ? Boolean(granted) : undefined,
          consentDate:   consentType === 'gdpr'      ? new Date()       : undefined,
          consentIp:     consentType === 'gdpr'      ? req.ip           : undefined,
          marketingOptIn: consentType === 'marketing' ? Boolean(granted) : undefined,
        },
      }),
    ]);

    await auditService.log({
      userId:    req.user.id,
      action:    granted ? 'CONSENT_GIVEN' : 'CONSENT_WITHDRAWN',
      resource:  `consent:${consentType}`,
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
      details:   { consentType, granted, version },
    });

    res.json({ message: 'Consent recorded', consentType, granted, timestamp: new Date() });
  } catch (err) {
    logger.error('Consent record error', { error: err.message });
    res.status(500).json({ error: 'Failed to record consent' });
  }
}

/**
 * POST /api/privacy/export
 * GDPR Article 20 — Right to data portability
 * CCPA § 1798.100 — Right to know
 */
async function requestExport(req, res) {
  try {
    const existing = await prisma.dataRequest.findFirst({
      where: { userId: req.user.id, type: 'export', status: { in: ['PENDING', 'PROCESSING'] } },
    });
    if (existing) {
      return res.status(409).json({ error: 'A data export request is already in progress', requestId: existing.id });
    }

    const dataRequest = await prisma.dataRequest.create({
      data: {
        userId:    req.user.id,
        type:      'export',
        status:    'PROCESSING',
        requestIp: req.ip,
      },
    });

    await auditService.log({
      userId:    req.user.id,
      action:    'DATA_EXPORT',
      resource:  `data_request:${dataRequest.id}`,
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
    });

    // Build export payload (async — in production this would be queued)
    const [user, reports, consentHistory, auditLogs] = await Promise.all([
      prisma.user.findUnique({
        where:  { id: req.user.id },
        select: { id: true, email: true, name: true, avatar: true, provider: true, plan: true, createdAt: true, consentGdpr: true, consentDate: true, marketingOptIn: true },
      }),
      prisma.report.findMany({
        where:  { userId: req.user.id, deletedAt: null },
        select: { id: true, module: true, reportType: true, title: true, tokenCount: true, createdAt: true },
      }),
      prisma.consentRecord.findMany({ where: { userId: req.user.id }, orderBy: { createdAt: 'desc' } }),
      prisma.auditLog.findMany({
        where:   { userId: req.user.id },
        orderBy: { createdAt: 'desc' },
        take:    500,
        select:  { action: true, resource: true, outcome: true, ipAddress: true, createdAt: true },
      }),
    ]);

    const exportPayload = {
      exportedAt:        new Date().toISOString(),
      requestedBy:       user.email,
      dataController:    'Corverxis Technologies Ltd',
      dpo:               config.compliance.dpoEmail,
      legalBasis:        'GDPR Article 20 — Right to Data Portability',
      profile:           user,
      reports:           reports, // Note: actual report content excluded for security; contact DPO for full export
      consentHistory,
      activityLog:       auditLogs,
      retentionPolicy:   `Data retained for ${user.plan === 'FREE' ? 90 : 365} days after account deletion`,
    };

    // Mark complete
    await prisma.dataRequest.update({
      where: { id: dataRequest.id },
      data:  { status: 'COMPLETED', completedAt: new Date() },
    });

    res.json({
      message: 'Data export complete',
      requestId: dataRequest.id,
      data: exportPayload,
    });
  } catch (err) {
    logger.error('Data export error', { error: err.message });
    res.status(500).json({ error: 'Data export failed' });
  }
}

/**
 * POST /api/privacy/delete
 * GDPR Article 17 — Right to erasure ("right to be forgotten")
 * CCPA § 1798.105 — Right to delete
 */
async function requestDeletion(req, res) {
  try {
    // Check for legal hold
    const holds = await prisma.dataRequest.findFirst({
      where: { userId: req.user.id, legalHold: true },
    });
    if (holds) {
      return res.status(403).json({
        error: 'Account is subject to a legal hold and cannot be deleted at this time.',
        code:  'LEGAL_HOLD',
        holdReason: holds.holdReason,
      });
    }

    // Check SEC retention on reports
    const retainedReports = await prisma.report.count({
      where: { userId: req.user.id, deletedAt: null, retainUntil: { gt: new Date() } },
    });
    if (retainedReports > 0) {
      return res.status(403).json({
        error:  `${retainedReports} reports are within the SEC 7-year retention window and cannot be deleted yet.`,
        code:   'SEC_RETENTION',
        count:  retainedReports,
      });
    }

    const dataRequest = await prisma.dataRequest.create({
      data: { userId: req.user.id, type: 'delete', status: 'PROCESSING', requestIp: req.ip },
    });

    // Soft-delete and anonymise PII (GDPR — pseudonymisation)
    const anon = `deleted_${Date.now()}`;
    await prisma.$transaction([
      prisma.user.update({
        where: { id: req.user.id },
        data: {
          email:      `${anon}@deleted.invalid`,
          name:       'Deleted User',
          avatar:     null,
          isActive:   false,
          deletedAt:  new Date(),
          providerId: anon,
        },
      }),
      // Revoke all sessions
      prisma.session.updateMany({
        where: { userId: req.user.id },
        data:  { isRevoked: true, revokedAt: new Date(), revokedReason: 'account_deleted' },
      }),
    ]);

    await auditService.log({
      userId:    req.user.id,
      action:    'DATA_DELETE_REQUEST',
      resource:  `user:${req.user.id}`,
      outcome:   'success',
      ipAddress: req.ip,
      requestId: req.requestId,
    });

    await prisma.dataRequest.update({
      where: { id: dataRequest.id },
      data:  { status: 'COMPLETED', completedAt: new Date() },
    });

    // Clear auth cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    res.json({
      message:   'Account and personal data deleted. Goodbye.',
      requestId: dataRequest.id,
      note:      'Financial reports within the SEC 7-year retention period are retained in anonymised form as required by law.',
    });
  } catch (err) {
    logger.error('Deletion error', { error: err.message });
    res.status(500).json({ error: 'Deletion request failed' });
  }
}

/**
 * GET /api/privacy/policy
 * Machine-readable privacy policy metadata
 */
async function policyMeta(req, res) {
  res.json({
    controller:       'Corverxis Technologies Ltd',
    dpo:              config.compliance.dpoEmail,
    policyVersion:    config.compliance.policyVersion,
    lastUpdated:      '2025-01-01',
    jurisdiction:     ['GDPR (EU)', 'CCPA (California)', 'PIPEDA (Canada)', 'UK GDPR'],
    legalBases:       ['Consent', 'Legitimate Interest', 'Contract Performance'],
    dataCategories:   ['Identity', 'Financial reports', 'Usage/activity', 'Technical logs'],
    retentionPeriods: {
      freeAccounts:       '90 days after deletion',
      paidAccounts:       '365 days after deletion',
      financialReports:   '7 years (SEC Rule 17a-4)',
      auditLogs:          '7 years (SOC2 Type II)',
      sessionLogs:        '90 days',
    },
    subprocessors:    ['Anthropic (AI processing)', 'Render.com (hosting)', 'Neon/PostgreSQL (database)'],
    rightsExercise:   `${config.frontend.url}/privacy`,
    contactEmail:     config.compliance.dpoEmail,
  });
}

module.exports = { recordConsent, requestExport, requestDeletion, policyMeta };
