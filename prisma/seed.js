'use strict';
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  console.log('🌱  Seeding NexGen Finance database…');

  // System config defaults
  const configs = [
    { key: 'FREE_TRIAL_LIMIT',     value: '10' },
    { key: 'PRO_MONTHLY_REPORTS',  value: '500' },
    { key: 'ENT_MONTHLY_REPORTS',  value: 'unlimited' },
    { key: 'DATA_RETENTION_FREE',  value: '90' },
    { key: 'DATA_RETENTION_PRO',   value: '365' },
    { key: 'DATA_RETENTION_ENT',   value: '2555' }, // 7 years SEC
    { key: 'MAINTENANCE_MODE',     value: 'false' },
    { key: 'POLICY_VERSION',       value: '1.0.0' },
  ];

  for (const cfg of configs) {
    await prisma.systemConfig.upsert({
      where:  { key: cfg.key },
      update: { value: cfg.value },
      create: cfg,
    });
  }

  console.log('✅  System config seeded');
  console.log('🎉  Database seeding complete');
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
