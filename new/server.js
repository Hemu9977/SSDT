import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Set environment flag for middleware
process.env.WC_SERVER = 'true';

const app = express();
const PORT = process.env.PORT || 3002;

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight/heavy execution pools (container-local backpressure)
// ─────────────────────────────────────────────────────────────────────────────

function getInt(name, def) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : def;
}

const WC_MAX_QUEUE_SIZE = getInt('WEBCHECK_MAX_QUEUE_SIZE', 200);
const WC_QUEUE_TIMEOUT_MS = getInt('WEBCHECK_QUEUE_TIMEOUT_MS', 300_000);
const WC_LIGHT_CONCURRENCY = getInt('WEBCHECK_LIGHT_SCAN_CONCURRENCY', 8);
const WC_HEAVY_CONCURRENCY = getInt('WEBCHECK_HEAVY_SCAN_CONCURRENCY', 2);
const WC_PER_SCAN_CONCURRENCY = getInt('WEBCHECK_PER_SCAN_TYPE_CONCURRENCY', 2);

const LIGHT_SCANS = new Set([
  'headers', 'cookies', 'redirects', 'dns', 'robots-txt', 'sitemap',
  'tech-stack', 'status',
  'hsts', 'security-txt', 'block-lists', 'social-tags', 'linked-pages',
  'mail-config', 'http-security', 'get-ip', 'dns-server', 'dnssec',
  'txt-records', 'carbon', 'archives',
]);

const HEAVY_SCANS = new Set([
  'whois', 'tls', 'ssl', 'ports', 'trace-route', 'firewall', 'quality', 'legacy-rank',
]);

function memSnapshot() {
  const mu = process.memoryUsage();
  return {
    rssMB: Number((mu.rss / 1048576).toFixed(1)),
    heapUsedMB: Number((mu.heapUsed / 1048576).toFixed(1)),
  };
}

class BoundedQueue {
  constructor({ name, concurrency, maxQueueSize, queueTimeoutMs }) {
    this.name = name;
    this.concurrency = Math.max(1, concurrency);
    this.maxQueueSize = Number.isFinite(maxQueueSize) ? maxQueueSize : 200;
    this.queueTimeoutMs = Math.max(0, queueTimeoutMs || 0);
    this.active = 0;
    this.queue = [];
  }

  stats() {
    return { name: this.name, active: this.active, queued: this.queue.length, concurrency: this.concurrency };
  }

  _drain() {
    while (this.active < this.concurrency && this.queue.length > 0) {
      const entry = this.queue.shift();
      if (entry.timeoutHandle) clearTimeout(entry.timeoutHandle);
      this.active++;
      Promise.resolve()
        .then(entry.fn)
        .then(
          (res) => { this.active--; entry.resolve(res); this._drain(); },
          (err) => { this.active--; entry.reject(err); this._drain(); }
        );
    }
  }

  run(fn) {
    if (this.queue.length >= this.maxQueueSize) {
      const err = new Error(`${this.name}: queue_full`);
      err.code = 'WEBCHECK_QUEUE_FULL';
      throw err;
    }

    return new Promise((resolve, reject) => {
      const entry = { fn, resolve, reject, timeoutHandle: null };
      if (this.queueTimeoutMs > 0) {
        entry.timeoutHandle = setTimeout(() => {
          const idx = this.queue.indexOf(entry);
          if (idx >= 0) this.queue.splice(idx, 1);
          const err = new Error(`${this.name}: queue_timeout`);
          err.code = 'WEBCHECK_QUEUE_TIMEOUT';
          reject(err);
        }, this.queueTimeoutMs);
      }
      this.queue.push(entry);
      this._drain();
    });
  }
}

const lightQueue = new BoundedQueue({
  name: 'webcheck/light',
  concurrency: WC_LIGHT_CONCURRENCY,
  maxQueueSize: WC_MAX_QUEUE_SIZE,
  queueTimeoutMs: WC_QUEUE_TIMEOUT_MS,
});

const heavyQueue = new BoundedQueue({
  name: 'webcheck/heavy',
  concurrency: WC_HEAVY_CONCURRENCY,
  maxQueueSize: WC_MAX_QUEUE_SIZE,
  queueTimeoutMs: WC_QUEUE_TIMEOUT_MS,
});

const perTypeActive = new Map();
function perTypeEnter(scanType) {
  const cur = perTypeActive.get(scanType) || 0;
  if (cur >= WC_PER_SCAN_CONCURRENCY) {
    const err = new Error(`webcheck/${scanType}: per_scan_concurrency_exceeded`);
    err.code = 'WEBCHECK_QUEUE_FULL';
    throw err;
  }
  perTypeActive.set(scanType, cur + 1);
}
function perTypeExit(scanType) {
  const cur = perTypeActive.get(scanType) || 0;
  perTypeActive.set(scanType, Math.max(0, cur - 1));
}

function chooseQueue(scanType) {
  return HEAVY_SCANS.has(scanType) ? heavyQueue : lightQueue;
}

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// List of all available scan scripts
const SCAN_TYPES = [
  'ssl', 'dns', 'headers', 'cookies', 'firewall', 'ports',
  'screenshot', 'tech-stack', 'hsts', 'security-txt', 'block-lists',
  'social-tags', 'linked-pages', 'robots-txt', 'sitemap', 'status',
  'redirects', 'mail-config', 'trace-route', 'http-security', 'get-ip',
  'dns-server', 'dnssec', 'txt-records', 'carbon', 'archives',
  'legacy-rank', 'whois', 'tls', 'quality'
];

// Dynamic route handler for all scan types
SCAN_TYPES.forEach(scanType => {
  app.get(`/api/${scanType}`, async (req, res) => {
    try {
      const queue = chooseQueue(scanType);

      // Queue + concurrency guard for overload protection.
      const t0 = Date.now();
      const qStatsBefore = queue.stats();

      // Dynamically import the handler
      const module = await import(`./scripts/${scanType}.js`);
      const handler = module.handler || module.default;

      await queue.run(async () => {
        perTypeEnter(scanType);
        try {
          const s = queue.stats();
          console.log(
            `[WebCheckContainer] start scanType=${scanType} ` +
            `active=${s.active} queued=${s.queued} ` +
            `lightActive=${lightQueue.stats().active} lightQueued=${lightQueue.stats().queued} ` +
            `heavyActive=${heavyQueue.stats().active} heavyQueued=${heavyQueue.stats().queued} ` +
            `mem=${JSON.stringify(memSnapshot())}`
          );

          // Call the handler with express request/response
          await handler(req, res);
        } finally {
          perTypeExit(scanType);
          const dur = Date.now() - t0;
          console.log(
            `[WebCheckContainer] done scanType=${scanType} durationMs=${dur} ` +
            `queuedAtStart=${qStatsBefore.queued} activeAtStart=${qStatsBefore.active}`
          );
        }
      });
    } catch (error) {
      console.error(`[${scanType}] Error:`, error.message);

      // Backpressure responses are explicit 503 (transient).
      if (error.code === 'WEBCHECK_QUEUE_FULL' || error.code === 'WEBCHECK_QUEUE_TIMEOUT') {
        return res.status(503).json({
          error: 'WebCheck overloaded',
          type: error.code,
          scanType,
          light: lightQueue.stats(),
          heavy: heavyQueue.stats(),
          mem: memSnapshot(),
        });
      }

      res.status(500).json({
        error: `Failed to execute ${scanType} scan`,
        details: error.message
      });
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    availableScans: SCAN_TYPES,
    queues: {
      light: lightQueue.stats(),
      heavy: heavyQueue.stats(),
    },
    mem: memSnapshot(),
  });
});

// List available endpoints
app.get('/api', (req, res) => {
  res.json({
    message: 'WebCheck API',
    endpoints: SCAN_TYPES.map(type => `/api/${type}?url=<target>`),
    usage: 'Add ?url=example.com to any endpoint'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    availableEndpoints: SCAN_TYPES.map(type => `/api/${type}`)
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('\n========================================');
  console.log('🔍 WebCheck Server Started');
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`📋 ${SCAN_TYPES.length} scan types available`);
  console.log('========================================\n');
});

export default app;
