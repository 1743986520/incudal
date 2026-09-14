#!/bin/sh
set -e

CERT_SOURCE_DIR=/run/incudal-certs
CERT_TARGET_DIR=/app/server/certs

# Bind-mounted private keys are commonly root:root 0600 on the Docker host.
# Copy them into a container-owned directory so the unprivileged application
# can read them without weakening permissions on the host copy.
mkdir -p "$CERT_TARGET_DIR"
if [ -f "$CERT_SOURCE_DIR/client.crt" ]; then
  cp "$CERT_SOURCE_DIR/client.crt" "$CERT_TARGET_DIR/client.crt"
  chown incudal:nodejs "$CERT_TARGET_DIR/client.crt"
  chmod 0644 "$CERT_TARGET_DIR/client.crt"
fi
if [ -f "$CERT_SOURCE_DIR/client.key" ]; then
  cp "$CERT_SOURCE_DIR/client.key" "$CERT_TARGET_DIR/client.key"
  chown incudal:nodejs "$CERT_TARGET_DIR/client.key"
  chmod 0600 "$CERT_TARGET_DIR/client.key"
fi

echo "🔄 Running database migrations..."
cd /app/server
su-exec incudal:nodejs npx prisma migrate deploy

echo "🚀 Starting application..."
cd /app
exec su-exec incudal:nodejs node server/dist/app.js
