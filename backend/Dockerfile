# ─── SentinelX backend image ────────────────────────────────────────────────
# Multi-stage: build TypeScript, then ship a lean runtime. better-sqlite3 is a
# native module, so the build stage includes the toolchain to compile it.
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Install only production deps (recompiles better-sqlite3 against runtime node).
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev && apt-get purge -y python3 make g++ && apt-get autoremove -y
COPY --from=build /app/dist ./dist
# Run as the non-root user that the base image already provides.
RUN mkdir -p /data /app/storage && chown -R node:node /data /app
USER node
ENV SQLITE_PATH=/data/sentinelx.db
ENV UPLOAD_DIR=/app/storage/uploads
EXPOSE 4000
# Seed on first boot, then start. Seeding is idempotent.
CMD ["sh", "-c", "node dist/db/seed.js && node dist/server.js"]
