'use strict';
const crypto = require('crypto');
const config = require('../config');

const ALGORITHM  = 'aes-256-gcm';
const KEY_LENGTH = 32;  // bytes
const IV_LENGTH  = 16;
const TAG_LENGTH = 16;

// Derive a 32-byte key from the hex env var
const masterKey = Buffer.from(config.encryption.key, 'hex');
if (masterKey.length !== KEY_LENGTH) {
  throw new Error(`ENCRYPTION_KEY must be a ${KEY_LENGTH * 2}-char hex string (${KEY_LENGTH} bytes)`);
}

/**
 * Encrypt plaintext string → "iv:tag:ciphertext" (all hex)
 */
function encrypt(plaintext) {
  if (!plaintext) return '';
  const iv         = crypto.randomBytes(IV_LENGTH);
  const cipher     = crypto.createCipheriv(ALGORITHM, masterKey, iv);
  const encrypted  = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag        = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt "iv:tag:ciphertext" → plaintext string
 */
function decrypt(ciphertext) {
  if (!ciphertext) return '';
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Invalid ciphertext format');

  const iv       = Buffer.from(ivHex,  'hex');
  const tag      = Buffer.from(tagHex, 'hex');
  const enc      = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(enc), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * SHA-256 content hash (tamper detection for SEC audit trail)
 */
function hash(data) {
  return crypto.createHash('sha256').update(String(data)).digest('hex');
}

/**
 * Constant-time string comparison (timing-safe)
 */
function safeCompare(a, b) {
  const aBuf = Buffer.from(String(a));
  const bBuf = Buffer.from(String(b));
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Generate a cryptographically secure random token
 */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = { encrypt, decrypt, hash, safeCompare, randomToken };
