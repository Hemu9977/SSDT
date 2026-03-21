const mongoose = require('mongoose');
const dns = require('dns');
require('dotenv').config();

// Set DNS servers explicitly to resolve ECONNREFUSED on some networks for Atlas SRV
dns.setServers(['8.8.8.8', '1.1.1.1']);

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
  try {
    // Check if already connected or connecting
    if (mongoose.connection.readyState === 1 || mongoose.connection.readyState === 2) {
      return;
    }
    
    // Mongoose handles reconnection automatically once the initial connection is established.
    // We only need retry logic for the VERY FIRST connection attempt.
    await mongoose.connect(process.env.MONGO_URI, {
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