require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
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

// ─── STRIPE WEBHOOK — must come BEFORE express.json() —───────────────────────────
// Stripe requires the raw body (Buffer) to verify the webhook signature.
// Mounting it here with express.raw() ensures json() middleware is NOT applied.
if (process.env.STRIPE_SECRET_KEY) {
  const stripeWebhookHandler = require('./routes/stripeRoutes');
  app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }), stripeWebhookHandler);
  console.log('✅ Stripe webhook endpoint mounted at /api/stripe/webhook');
}

// Connect to database and initialize GridFS
connectDB().then(() => {
  // Initialize GridFS after MongoDB connection is established
  try {
    gridfsService.initialize('zap_reports');
    gridfsService.initialize('zap_auth_reports');
    gridfsService.initialize('webcheck_results');
    console.log('✅ GridFS initialized (buckets: zap_reports, zap_auth_reports, webcheck_results)');
  } catch (error) {
    console.error('⚠️  GridFS initialization failed:', error.message);
    console.error('   Large file storage may not work properly');
  }

  // Start cleanup job for expired scans and orphaned data
  try {
    startCleanupJob();
    console.log('✅ Cleanup job scheduler started');
  } catch (error) {
    console.error('⚠️  Cleanup job initialization failed:', error.message);
  }
});

app.set('trust proxy', 1);

app.use(cors({
  origin: [
    process.env.CLIENT_URL || 'http://localhost:3000',
    'http://localhost:3002',
    'http://localhost:3003'
  ],
  credentials: true
}));
app.use(express.json({ extended: false, limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

app.use('/auth', authLimiter, require('./routes/auth'));
app.use('/api/vt', apiLimiter, scanLimiter, require('./routes/virustotalRoutes'));
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

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
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

const PORT = process.env.PORT || 3001;

// Create HTTP server and attach Socket.IO
const server = http.createServer(app);
initializeSocket(server);

server.listen(PORT, () => {
  console.log('\n=================================');
  console.log('🚀 Server started successfully!');
  console.log(`📡 Listening on port ${PORT}`);
  console.log('🔌 Socket.IO notifications enabled');
  console.log('=================================\n');
});