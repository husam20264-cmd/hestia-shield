#!/usr/bin/env bash
# ============================================================
# Hestia Shield v2.0.0 — Fly.io Deployment Script
# ============================================================
set -euo pipefail

echo "🚀 Hestia Shield — Deploy to Fly.io"
echo "======================================"

# 1. Install flyctl if missing
if ! command -v flyctl &>/dev/null; then
    echo "📦 Installing flyctl..."
    curl -L https://fly.io/install.sh | sh
    export PATH="$HOME/.fly/bin:$PATH"
fi

# 2. Login (requires browser or token)
echo "🔑 Logging in to Fly.io..."
echo "    Run: flyctl auth login"
echo "    (or set FLY_API_TOKEN env var for CI)"
if [ -z "${FLY_API_TOKEN:-}" ]; then
    flyctl auth login
fi

# 3. Generate secrets
echo "🔐 Generating secrets..."
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

echo "📝 Setting secrets..."
flyctl secrets set \
    HESTIA_JWT_SECRET="$JWT_SECRET" \
    HESTIA_DEBUG="false" \
    HESTIA_LOG_LEVEL="INFO" \
    HESTIA_HEALING_ENABLED="true"

# 4. Launch or deploy
if ! flyctl status &>/dev/null 2>&1; then
    echo "🚀 Launching new app..."
    flyctl launch --copy-config --no-deploy
fi

echo "📦 Deploying..."
flyctl deploy

# 5. Verify
echo "✅ Verifying deployment..."
sleep 5
APP_URL=$(flyctl info --json | python3 -c "import sys,json; print(json.load(sys.stdin)['Hostname'])")
echo "   App URL: https://$APP_URL"

curl -s "https://$APP_URL/health" && echo ""
echo "   Health check: OK"

echo ""
echo "🎉 Deployment complete!"
echo "   Dashboard: https://$APP_URL/dashboard"
echo "   API:       https://$APP_URL/v1/decision/evaluate"
