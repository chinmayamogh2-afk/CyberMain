#!/usr/bin/env bash
# Generates a .env.docker with fresh secrets. Usage: ./scripts/gen-secrets.sh > .env.docker
set -euo pipefail
cat <<ENV
SESSION_SECRET=$(openssl rand -hex 32)
CSRF_SECRET=$(openssl rand -hex 32)
DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)
ENABLE_DEMO_SEED=true
ENV
