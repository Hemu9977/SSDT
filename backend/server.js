if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const connectDB = require('./db');
const { apiLimiter, authLimiter, scanLimiter } = require('./middleware/rateLimiter');
const gridfsService = require('./services/gridfsService'); // GridFS for ZAP reports
const { startCleanupJob } = require('./jobs/cleanupJob'); // Scheduled cleanup
const { initializeSocket } = require('./services/notificationService');
const { startScheduler } = require('./services/schedulerService'); // Scan scheduler

// IMPORT ZAP ROUTES
const zapRoutes = require('./routes/zapRoutes');
const zapAuthRoutes = require('./routes/zapAuthRoutes');
const webCheckRoutes = require('./routes/webCheckRoutes');

// Validate required environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error('❌ ERROR: Missing required environment variables:');
  missingVars.forEach(varName => console.error(`   - ${varName}`));
  process.exit(1);
}

const app = express();

app.use(helmet({
  // Google OAuth popup needs window.closed access across origins;
  // helmet's default "same-origin" blocks it → use allow-popups variant.
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
}));
app.set('trust proxy', 1);

// Comma-separated list in FRONTEND_URL supports multiple production domains,
// e.g. "https://fortexa.aevus.jp"
const defaultFrontendOrigins = ['https://fortexa.aevus.jp'];
const rawFrontendOrigins = process.env.FRONTEND_URL;
if (!rawFrontendOrigins && process.env.NODE_ENV === 'production') {
  console.warn('[CORS] FRONTEND_URL is not set in production; using safe defaults.');
}
const allowedOriginsSet = new Set(
  (rawFrontendOrigins || defaultFrontendOrigins.join(','))
    .split(',').map(o => o.trim()).filter(Boolean)
);
if (process.env.NODE_ENV !== 'production') {
  ['http://localhost:3000', 'http://localhost:3002', 'http://localhost:3003']
    .forEach(o => allowedOriginsSet.add(o));
}

const corsOptions = {
  origin(origin, callback) {
    // Allow server-to-server calls (no Origin header) and known origins
    if (!origin || allowedOriginsSet.has(origin)) return callback(null, true);
    console.warn(`[CORS] Blocked request from: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-auth-token', 'Authorization'],
  maxAge: 86400, // cache preflight 24h
};

app.use(cors(corsOptions));
// Explicit preflight handler — must come before rate limiters and routes so
// OPTIONS requests never reach authLimiter or route handlers (which assume a body).
app.options(/.*/, cors(corsOptions));

// ─── STRIPE WEBHOOK — must come BEFORE express.json() ────────────────────────
// Stripe requires the raw body (Buffer) to verify the webhook signature.
// Mounting it here with express.raw() ensures json() middleware is NOT applied.
if (process.env.STRIPE_SECRET_KEY) {
  app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
  console.log('✅ Stripe webhook endpoint mounted at /api/stripe/webhook');
}
app.use(express.json({ extended: false, limit: '10mb' }));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

app.use('/auth', authLimiter, require('./routes/auth'));
app.use('/api/scan', apiLimiter, scanLimiter, require('./routes/virustotalRoutes'));
app.use('/api/pagespeed', apiLimiter, require('./routes/pageSpeedRoutes'));

// 👇 REGISTER PROFILE ROUTE
app.use('/api/profile', apiLimiter, require('./routes/profile'));

// 👇 REGISTER STRIPE ROUTES (authenticated plan/checkout endpoints)
if (process.env.STRIPE_SECRET_KEY) {
  app.use('/api/stripe', apiLimiter, require('./routes/stripeRoutes'));
  console.log('✅ Stripe API routes mounted at /api/stripe');
}

// 👇 REGISTER ZAP ROUTE
app.use('/api/zap', apiLimiter, scanLimiter, zapRoutes);

// 👇 REGISTER ZAP AUTH ROUTES (Authenticated scanning on port 8081)
app.use('/api/zap-auth', apiLimiter, scanLimiter, zapAuthRoutes);

// 👇 REGISTER WEBCHECK ROUTES
app.use('/api/webcheck', apiLimiter, scanLimiter, webCheckRoutes);

// 👇 REGISTER TRANSLATE ROUTES (Gemini-powered translation)
app.use('/api/translate', apiLimiter, require('./routes/translateRoutes'));

// 👇 REGISTER URLSCAN ROUTES
app.use('/api/urlscan', apiLimiter, require('./routes/urlscanRoutes'));

// 👇 REGISTER ORGANIZATION ROUTES
app.use('/api/org', apiLimiter, require('./routes/orgRoutes'));
// After the /api/org line:
app.use('/api/notifications', apiLimiter, require('./routes/notificationRoutes'));
app.use('/api/schedules', apiLimiter, require('./routes/scheduleRoutes'));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', message: `Cannot ${req.method} ${req.path}` });
});

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

const PORT = process.env.PORT || 3000;

// Create HTTP server and attach Socket.IO
const server = http.createServer(app);
initializeSocket(server);

// Graceful shutdown — ECS sends SIGTERM on deploy/scale-in, waits 30s then SIGKILL
const shutdown = (signal) => {
  console.log(`\n${signal} received. Closing server gracefully...`);
  server.close(() => {
    console.log('✅ HTTP server closed. Exiting.');
    process.exit(0);
  });
  // Force-exit if server hasn't closed within 25s (before ECS sends SIGKILL at 30s)
  setTimeout(() => {
    console.error('⚠️  Graceful shutdown timed out. Forcing exit.');
    process.exit(1);
  }, 25000);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Promise Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

async function startServer() {
  try {
    await connectDB();

    try {
      gridfsService.initialize('zap_reports');
      gridfsService.initialize('zap_auth_reports');
      gridfsService.initialize('webcheck_results');
      console.log('✅ GridFS initialized (buckets: zap_reports, zap_auth_reports, webcheck_results)');
    } catch (error) {
      console.error('⚠️  GridFS initialization failed:', error.message);
      console.error('   Large file storage may not work properly');
    }

    try {
      startCleanupJob();
      console.log('✅ Cleanup job scheduler started');
    } catch (error) {
      console.error('⚠️  Cleanup job initialization failed:', error.message);
    }

    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n=================================');
      console.log('🚀 Server started successfully!');
      console.log(`📡 Listening on port ${PORT}`);
      console.log('🔌 Socket.IO notifications enabled');
      console.log('=================================\n');
    });

  } catch (err) {
    console.error(' Fatal: could not connect to MongoDB on startup:', err.message);
    process.exit(1);
  }
}

startServer();