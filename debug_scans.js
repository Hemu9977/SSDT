const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../backend/.env') });

const ScanResult = require('../backend/models/ScanResult');

async function checkScans() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const scans = await ScanResult.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .select('analysisId target status userId triggerSource createdAt');

    console.log('Latest Scans:');
    scans.forEach(s => {
      console.log(`- ${s.analysisId} | ${s.target} | ${s.status} | User: ${s.userId} | Source: ${s.triggerSource} | Created: ${s.createdAt}`);
    });

    const scheduledPending = await ScanResult.find({
      triggerSource: 'scheduled',
      status: { $in: ['pending', 'running', 'combining'] }
    });
    console.log(`\nScheduled Scans in progress: ${scheduledPending.length}`);

    await mongoose.disconnect();
  } catch (err) {
    console.error('Error:', err);
  }
}

checkScans();
