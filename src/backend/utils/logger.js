'use strict';
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const config = require('../config');

const { combine, timestamp, json, colorize, simple, errors } = winston.format;

const logDir = path.resolve(config.log.dir);

// Sanitize sensitive fields before logging
const sanitize = winston.format((info) => {
  const sensitive = ['password', 'token', 'secret', 'apiKey', 'authorization', 'cookie'];
  if (info.details && typeof info.details === 'object') {
    sensitive.forEach((k) => {
      if (info.details[k]) info.details[k] = '[REDACTED]';
    });
  }
  return info;
});

const transports = [
  // Console — dev: human-readable, prod: JSON
  new winston.transports.Console({
    format: config.isProd()
      ? combine(timestamp(), sanitize(), json())
      : combine(colorize(), simple()),
  }),
];

if (config.isProd()) {
  // Rotating file — application logs
  transports.push(new DailyRotateFile({
    dirname:       logDir,
    filename:      'nexgen-%DATE%.log',
    datePattern:   'YYYY-MM-DD',
    zippedArchive: true,
    maxSize:       '20m',
    maxFiles:      '90d',
    format:        combine(timestamp(), sanitize(), errors({ stack: true }), json()),
  }));

  // Separate security / audit log file (SOC2 requirement)
  transports.push(new DailyRotateFile({
    dirname:       path.join(logDir, 'audit'),
    filename:      'audit-%DATE%.log',
    datePattern:   'YYYY-MM-DD',
    zippedArchive: true,
    maxSize:       '50m',
    maxFiles:      '2555d', // 7 years — SEC retention
    level:         'info',
    format:        combine(timestamp(), sanitize(), json()),
  }));
}

const logger = winston.createLogger({
  level:      config.log.level,
  transports,
  exitOnError: false,
});

// Convenience method for audit events
logger.audit = (message, meta = {}) => {
  logger.info(message, { ...meta, audit: true });
};

module.exports = logger;
