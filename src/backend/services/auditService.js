'use strict';
const prisma  = require('../config/prisma');
const { hash } = require('./encryptionService');
const logger  = require('../utils/logger');

let lastHash = null; // in-memory chain head; reloaded from DB on start

/**
 * Bootstrap — load the hash of the last audit entry to continue the chain
 */
async function init() {
  try {
    const last = await prisma.auditLog.findFirst({ orderBy: { createdAt: 'desc' } });
    lastHash = last?.entryHash || 'GENESIS';
    logger.info('Audit service initialized', { chainHead: lastHash.slice(0, 16) + '…' });
  } catch (err) {
    logger.warn('Could not load last audit hash — starting new chain', { error: err.message });
    lastHash = 'GENESIS';
  }
}

/**
 * Write a tamper-evident audit log entry.
 * Each entry includes a hash of itself chained to the previous entry's hash.
 *
 * SOC2 CC7.2 — Monitors system components for anomalies
 * SOC2 CC9.2 — Communicates information about changes / incidents
 */
async function log({ userId, action, resource, details, outcome, ipAddress, userAgent, requestId, sessionId }) {
  try {
    const prev = lastHash || 'GENESIS';

    // Build the entry content for hashing (excluding entryHash itself)
    const entryContent = JSON.stringify({
      userId, action, resource, details, outcome,
      ipAddress, userAgent, requestId, sessionId,
      prevHash: prev,
      ts: new Date().toISOString(),
    });

    const entryHash = hash(entryContent);
    lastHash = entryHash;

    const log = await prisma.auditLog.create({
      data: {
        userId:    userId || null,
        action,
        resource:  resource || null,
        details:   details || {},
        outcome,
        ipAddress: ipAddress || null,
        userAgent: userAgent || null,
        requestId: requestId || null,
        sessionId: sessionId || null,
        prevHash:  prev,
        entryHash,
      },
    });

    // Also write to secure log file
    logger.audit('AUDIT_EVENT', {
      auditId:  log.id,
      userId, action, resource, outcome, ipAddress,
      requestId, entryHash: entryHash.slice(0, 16) + '…',
    });

    return log;
  } catch (err) {
    // Never throw from audit — log to stderr and continue
    logger.error('Audit log write failed', { error: err.message, action, userId });
  }
}

/**
 * Verify chain integrity between two audit log IDs.
 * Returns { valid: boolean, brokenAt: id | null }
 */
async function verifyChain(fromId, toId) {
  const entries = await prisma.auditLog.findMany({
    where: {
      createdAt: {
        gte: (await prisma.auditLog.findUnique({ where: { id: fromId } }))?.createdAt,
        lte: (await prisma.auditLog.findUnique({ where: { id: toId   } }))?.createdAt,
      },
    },
    orderBy: { createdAt: 'asc' },
  });

  for (let i = 1; i < entries.length; i++) {
    const cur  = entries[i];
    const prev = entries[i - 1];
    if (cur.prevHash !== prev.entryHash) {
      return { valid: false, brokenAt: cur.id, brokenAfter: prev.id };
    }
  }
  return { valid: true, brokenAt: null };
}

module.exports = { init, log, verifyChain };
