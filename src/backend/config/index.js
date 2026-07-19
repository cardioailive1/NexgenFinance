'use strict';
require('dotenv').config();

/**
 * Central config with environment validation.
 * Throws on startup if required vars are missing.
 */

const required = (key) => {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
};

const optional = (key, def = '') => process.env[key] ?? def;

const config = {
  env:  optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '10000'), 10),

  // Database
  db: {
    url: required('DATABASE_URL'),
  },

  // JWT
  jwt: {
    accessSecret:  required('JWT_ACCESS_SECRET'),
    refreshSecret: required('JWT_REFRESH_SECRET'),
    accessTtl:     optional('JWT_ACCESS_TTL',  '15m'),
    refreshTtl:    optional('JWT_REFRESH_TTL', '30d'),
  },

  // Encryption (AES-256 for report data at rest)
  encryption: {
    key: required('ENCRYPTION_KEY'), // 32-byte hex string
  },

  // Session
  session: {
    secret: required('SESSION_SECRET'),
  },

  // Anthropic
  anthropic: {
    apiKey: required('ANTHROPIC_API_KEY'),
    model:  optional('ANTHROPIC_MODEL', 'claude-sonnet-4-6'),
  },

  // OAuth2 providers
  oauth: {
    google: {
      clientId:     optional('GOOGLE_CLIENT_ID'),
      clientSecret: optional('GOOGLE_CLIENT_SECRET'),
      callbackUrl:  optional('GOOGLE_CALLBACK_URL', 'https://nexgen-finance.onrender.com/api/auth/google/callback'),
    },
    github: {
      clientId:     optional('GITHUB_CLIENT_ID'),
      clientSecret: optional('GITHUB_CLIENT_SECRET'),
      callbackUrl:  optional('GITHUB_CALLBACK_URL', 'https://nexgen-finance.onrender.com/api/auth/github/callback'),
    },
    microsoft: {
      clientId:     optional('MICROSOFT_CLIENT_ID'),
      clientSecret: optional('MICROSOFT_CLIENT_SECRET'),
      callbackUrl:  optional('MICROSOFT_CALLBACK_URL', 'https://nexgen-finance.onrender.com/api/auth/microsoft/callback'),
      tenantId:     optional('MICROSOFT_TENANT_ID', 'common'),
    },
  },

  // CORS
  cors: {
    origins: optional('CORS_ORIGINS', 'http://localhost:3000').split(','),
  },

  // Redis (optional — rate limit fallback to memory if absent)
  redis: {
    url: optional('REDIS_URL', ''),
  },

  // Frontend
  frontend: {
    url: optional('FRONTEND_URL', 'http://localhost:10000'),
  },

  // Compliance
  compliance: {
    secRetentionYears: parseInt(optional('SEC_RETENTION_YEARS', '7'), 10),
    policyVersion:     optional('POLICY_VERSION', '1.0.0'),
    dpoEmail:          optional('DPO_EMAIL', 'privacy@corverxis.com'),
  },

  // Logging
  log: {
    level: optional('LOG_LEVEL', 'info'),
    dir:   optional('LOG_DIR', './logs'),
  },

  isProd: () => config.env === 'production',
  isDev:  () => config.env === 'development',
};

module.exports = config;
