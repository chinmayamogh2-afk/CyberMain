#!/usr/bin/env bash
# Reset SentinelX to a clean demonstration baseline.
set -euo pipefail
cd "$(dirname "$0")/../backend"
npm run db:reset
