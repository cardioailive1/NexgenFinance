##############################################################################
#  NexGen Finance — Multi-stage Dockerfile
#  Build: docker build -t nexgen-finance .
#  Run:   docker run -p 10000:10000 --env-file .env nexgen-finance
##############################################################################

# ── Stage 1: Dependencies ─────────────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app

# Install only production deps first for layer caching
COPY package*.json ./
COPY prisma/schema.prisma ./prisma/
RUN npm ci --omit=dev && npx prisma generate

# ── Stage 2: Production image ─────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app

# Security: run as non-root user
RUN addgroup --system --gid 1001 nexgen \
 && adduser  --system --uid 1001 nexgen

# Copy built artifacts
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/node_modules/.prisma ./node_modules/.prisma
COPY --chown=nexgen:nexgen . .

# Create log directory
RUN mkdir -p logs/audit && chown -R nexgen:nexgen logs

USER nexgen

EXPOSE 10000

# Healthcheck for orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:10000/health || exit 1

ENV NODE_ENV=production
CMD ["node", "src/backend/server.js"]
