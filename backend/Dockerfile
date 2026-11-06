# Node 24: the in-house header-grading fallback (@mdn/mdn-http-observatory)
# requires it, and Lighthouse 13 needs >= 22.19. Pinned to bookworm so the apt
# package names below stay valid.
FROM node:24-bookworm-slim

WORKDIR /app

# Chromium for Puppeteer (login detection/test, PDF) and for the in-house
# fallbacks (performance audit, page capture). fonts-noto-cjk: Japanese (and Chinese/
# Korean) pages would otherwise render as empty boxes in the screenshot and
# lay out differently under the audit.
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-liberation \
    fonts-noto-cjk \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libgbm1 \
    --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

# Intermediate-certificate bundle for the in-house header-grading fallback, as
# the public service it stands in for runs with: a site that serves an incomplete
# chain still gets graded instead of failing TLS. Only adds trust anchors; read
# at process start. Set after `npm ci`, which installs the file.
ENV NODE_EXTRA_CA_CERTS=/app/node_modules/node_extra_ca_certs_mozilla_bundle/ca_bundle/ca_intermediate_root_bundle.pem

COPY . .

EXPOSE 3001

# Container health check (Docker only — ECS ignores this and uses the task
# definition / ALB target-group checks). Probes the port the app listens on: the
# task definition sets PORT=3000, so the old hardcoded 3001 could never pass.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 3001) + '/ready', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# Run as non-root for security (node user is built into the node image)
USER node

CMD ["node", "--max-http-header-size=81920", "server.js"]
