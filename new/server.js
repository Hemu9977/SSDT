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
      // Dynamically import the handler
      const module = await import(`./scripts/${scanType}.js`);
      const handler = module.handler || module.default;

      // Call the handler with express request/response
      await handler(req, res);
    } catch (error) {
      console.error(`[${scanType}] Error:`, error.message);
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
    availableScans: SCAN_TYPES
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
