'use strict';
const { PrismaClient } = require('@prisma/client');
const logger = require('../utils/logger');

let prisma;

if (process.env.NODE_ENV === 'production') {
  prisma = new PrismaClient({
    log: [{ emit: 'event', level: 'error' }],
  });
} else {
  // Prevent multiple instances in hot-reload dev environments
  if (!global.__prisma) {
    global.__prisma = new PrismaClient({
      log: ['query', 'error', 'warn'],
    });
  }
  prisma = global.__prisma;
}

prisma.$on('error', (e) => {
  logger.error('Prisma error', { message: e.message, target: e.target });
});

module.exports = prisma;
