#!/bin/sh
# Deploys the relay to our VPS: ./deploy.sh [ssh host]. It ships the code,
# installs ws, and restarts the service. First run also creates the user,
# the systemd unit and the Traefik route.
set -e
HOST="${1:-vps-eu-1}"
tar czf - server.js relay.js package.json package-lock.json public deploy | ssh "$HOST" '
  set -e
  id horadric >/dev/null 2>&1 || useradd --system --home /opt/horadric-portal --shell /usr/sbin/nologin horadric
  mkdir -p /opt/horadric-portal
  cd /opt/horadric-portal
  tar xzf -
  npm ci --omit=dev --no-audit --no-fund --silent
  chown -R root:root /opt/horadric-portal
  cp deploy/horadric-portal.service /etc/systemd/system/horadric-portal.service
  cp deploy/horadric-portal.yaml /data/coolify/proxy/dynamic/horadric-portal.yaml
  systemctl daemon-reload
  systemctl enable --quiet horadric-portal
  systemctl restart horadric-portal
  sleep 1
  systemctl is-active horadric-portal
  curl -s http://10.0.0.1:43200/health
'
