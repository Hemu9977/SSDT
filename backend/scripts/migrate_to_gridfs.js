require('dotenv').config();
require('../utils/logRedaction').install(); // before anything that logs (utils/logRedaction.js)
const mongoose = require('mongoose');
const ScanResult = require('../models/ScanResult');
const gridfsService = require('../services/gridfsService');

async function migrateToGridFS() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ Connected to MongoDB');

        // Find scans with large embedded reports
        const scans = await ScanResult.find({
            $or: [
                { 'zapResult.htmlReport': { $exists: true } },
                { 'zapResult.jsonReport': { $exists: true } },
                { 'zapResult.xmlReport': { $exists: true } }
            ]
        });

        console.log(`Found ${scans.length} scans to migrate`);

        if (scans.length === 0) {
            console.log('No scans need migration. Exiting.');
            process.exit(0);
        }

        for (const scan of scans) {
            console.log(`\n📦 Migrating scan: ${scan.analysisId}`);

            const reportFiles = [];
            let migratedCount = 0;

            // Migrate HTML report
            if (scan.zapResult?.htmlReport) {
                try {
                    const htmlFileId = await gridfsService.uploadFile(
                        scan.zapResult.htmlReport,
                        `${scan.analysisId}-report.html`,
                        { scanId: scan.analysisId, format: 'html', type: 'full-report' }
                    );
                    reportFiles.push({ format: 'html', fileId: htmlFileId });
                    migratedCount++;
                    console.log(`  ✅ Migrated HTML report (${htmlFileId})`);
                } catch (error) {
                    console.error(`  ❌ Failed to migrate HTML report:`, error.message);
                }
            }

            // Migrate JSON report
            if (scan.zapResult?.jsonReport) {
                try {
                    const jsonData = typeof scan.zapResult.jsonReport === 'string'
                        ? scan.zapResult.jsonReport
                        : JSON.stringify(scan.zapResult.jsonReport);

                    const jsonFileId = await gridfsService.uploadFile(
                        jsonData,
                        `${scan.analysisId}-report.json`,
                        { scanId: scan.analysisId, format: 'json', type: 'full-report' }
                    );
                    reportFiles.push({ format: 'json', fileId: jsonFileId });
                    migratedCount++;
                    console.log(`  ✅ Migrated JSON report (${jsonFileId})`);
                } catch (error) {
                    console.error(`  ❌ Failed to migrate JSON report:`, error.message);
                }
            }

            // Migrate XML report
            if (scan.zapResult?.xmlReport) {
                try {
                    const xmlFileId = await gridfsService.uploadFile(
                        scan.zapResult.xmlReport,
                        `${scan.analysisId}-report.xml`,
                        { scanId: scan.analysisId, format: 'xml', type: 'full-report' }
                    );
                    reportFiles.push({ format: 'xml', fileId: xmlFileId });
                    migratedCount++;
                    console.log(`  ✅ Migrated XML report (${xmlFileId})`);
                } catch (error) {
                    console.error(`  ❌ Failed to migrate XML report:`, error.message);
                }
            }

            // Update scan document only if we successfully migrated at least one report
            if (migratedCount > 0) {
                try {
                    await ScanResult.findOneAndUpdate(
                        { _id: scan._id },
                        {
                            $set: { 'zapResult.reportFiles': reportFiles },
                            $unset: {
                                'zapResult.htmlReport': '',
                                'zapResult.jsonReport': '',
                                'zapResult.xmlReport': ''
                            }
                        }
                    );
                    console.log(`  ✅ Updated scan document (removed ${migratedCount} embedded reports)`);
                } catch (error) {
                    console.error(`  ❌ Failed to update scan document:`, error.message);
                }
            }
        }

        console.log('\n✅ Migration complete!');
        process.exit(0);

    } catch (error) {
        console.error('\n❌ Migration failed:', error);
        process.exit(1);
    }
}

// Run migration
migrateToGridFS();
