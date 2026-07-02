const mongoose = require('mongoose');
const dns = require('dns');

// ── DNS resolver configuration ────────────────────────────────────────────────
//
// Node.js has two independent DNS subsystems:
//
//   dns.lookup()      → getaddrinfo (OS resolver).  Reads /etc/hosts.
//                       Used by: net.createConnection, ioredis, plain axios.
//                       NOT affected by dns.setServers().
//
//   dns.resolve*()    → c-ares (Node.js async resolver).  Does NOT read /etc/hosts.
//                       Used by: dns.resolveSrv, dns.resolve4, cacheable-lookup.
//                       IS affected by dns.setServers().
//
// MongoDB Atlas bootstraps with mongodb+srv:// which requires dns.resolveSrv()
// (c-ares) to discover the replica set.  On some systems — particularly Windows
// where c-ares reads DNS servers from the registry — c-ares auto-detects
// 127.0.0.1 as the nameserver but nothing is listening on port 53, producing:
//   querySrv ECONNREFUSED localhost
// Explicitly setting Google DNS (8.8.8.8 / 1.1.1.1) makes c-ares bypass this.
//
// Why this is now safe after the WebCheck DNS fix:
//   • WebCheck container is accessed via IP (127.0.0.1:3002), so no DNS lookup fires.
//   • installSmartLookup() in httpClient.js routes loopback hostnames through
//     dns.lookup() (OS), bypassing cacheable-lookup's dns.resolve4() entirely.
//   • All remaining dns.resolve4() calls from cacheable-lookup target external
//     API hostnames which 8.8.8.8 handles correctly.
//
// On ECS Fargate: skip the override.  The VPC DNS at 169.254.169.253 handles
// both Atlas SRV queries and Docker service-name lookups (webcheck, zap-scanner).
// Overriding to 8.8.8.8 there would break internal service name resolution.

const IS_ECS = !!process.env.ECS_CONTAINER_METADATA_URI_V4;

if (!IS_ECS) {
  dns.setServers(['8.8.8.8', '1.1.1.1']);
  console.log('[DB] c-ares DNS overridden to 8.8.8.8/1.1.1.1 (local dev — Atlas SRV fix)');
} else {
  console.log('[DB] Running on ECS Fargate — using VPC DNS for Atlas SRV and service names');
}

const MAX_RETRIES = 5;
const RETRY_DELAY_MS = 5000; // 5 seconds

// Handle connection events (defined once outside the connect function)
mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB connected successfully');
});

mongoose.connection.on('disconnected', () => {
  console.warn('⚠️  MongoDB disconnected. Mongoose will attempt to reconnect automatically.');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
});

const connectDB = async (retryCount = 0) => {
  const uri = process.env.MONGO_URI;

  if (!uri) {
    console.error('❌ MONGO_URI is undefined. ECS secrets injection may have failed.');
    console.error('   Check: task execution role IAM, valueFrom ARN syntax, secret region.');
    process.exit(1);
  }

  // Accept both MongoDB Atlas (mongodb+srv://) and local/Docker MongoDB (mongodb://)
  if (
    !uri.startsWith('mongodb+srv://') &&
    !uri.startsWith('mongodb://')
  ) {
    const preview = uri.length > 12 ? uri.slice(0, 12) + '...[REDACTED]' : '[too short]';
    console.error(
      `❌ Invalid MONGO_URI. Expected mongodb:// or mongodb+srv://. Got: "${preview}"`
    );
    process.exit(1);
  }

  try {
    // Check if already connected or connecting
    if (mongoose.connection.readyState === 1 || mongoose.connection.readyState === 2) {
      return;
    }

    // Mongoose handles reconnection automatically once the initial connection is established.
    // We only need retry logic for the VERY FIRST connection attempt.
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 10000, // Increased to 10s for DNS stability
      heartbeatFrequencyMS: 10000,    // Check cluster health every 10s
      socketTimeoutMS: 45000,         // Close sockets after 45s of inactivity
    });

  } catch (err) {
    console.error(`❌ Initial MongoDB connection error (attempt ${retryCount + 1}/${MAX_RETRIES}):`, err.message);

    if (retryCount < MAX_RETRIES) {
      const nextRetry = retryCount + 1;
      const delay = RETRY_DELAY_MS * nextRetry; // Exponential backoff
      console.log(`🔄 Retrying initial connection in ${delay / 1000} seconds...`);

      return new Promise(resolve => {
        setTimeout(() => resolve(connectDB(nextRetry)), delay);
      });
    } else {
      console.error('💥 Max connection retries reached. Could not establish initial connection to MongoDB.');
      console.error('Check MONGO_URI and network connectivity.');
      process.exit(1);
    }
  }
};

module.exports = connectDB;