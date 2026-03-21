const mongoose = require('mongoose');
const { GridFSBucket } = mongoose.mongo; // Use mongoose's bundled mongodb to avoid BSON version mismatch
const stream = require('stream');

class GridFSService {
    constructor() {
        this.buckets = {};
    }

    initialize(bucketName = 'zap_reports') {
        if (!this.buckets[bucketName]) {
            const db = mongoose.connection.db;
            this.buckets[bucketName] = new GridFSBucket(db, {
                bucketName: bucketName
            });
        }
        return this.buckets[bucketName];
    }

    // Shorthand for ZAP bucket (backward compatibility)
    get bucket() {
        return this.initialize('zap_reports');
    }

    /**
     * Upload a file to GridFS with progress logging and optional callback
     * @param {Buffer|String} data - File data
     * @param {String} filename - Filename
     * @param {Object} metadata - Additional metadata
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     * @param {Number} timeout - Timeout in ms (default: 3600000 = 1 hour)
     * @param {Function} onProgress - Optional callback called with { percent, uploadedMB, totalMB, elapsed }
     * @returns {Promise<ObjectId>} - File ID
     */
    async uploadFile(data, filename, metadata = {}, bucketName = 'zap_reports', timeout = 3600000, onProgress = null) {
        const bucket = this.initialize(bucketName);

        // Convert string to buffer if needed
        const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const totalSize = buffer.length;
        const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(2);

        console.log(`[GridFS] 📤 Starting upload: ${filename} (${totalSizeMB}MB) to bucket: ${bucketName}`);
        const startTime = Date.now();

        return new Promise((resolve, reject) => {
            // Timeout scales with file size: 1 hour base + 1 min per 10MB
            const dynamicTimeout = Math.max(timeout, 3600000 + (totalSize / (10 * 1024 * 1024)) * 60000);
            console.log(`[GridFS] ⏱️ Upload timeout set to ${(dynamicTimeout / 1000 / 60).toFixed(1)} minutes`);

            const timeoutId = setTimeout(() => {
                reject(new Error(`GridFS upload timeout after ${(dynamicTimeout/1000/60).toFixed(1)} minutes for ${totalSizeMB}MB file`));
            }, dynamicTimeout);

            const uploadStream = bucket.openUploadStream(filename, {
                metadata: {
                    ...metadata,
                    fileSize: totalSize,
                    uploadDate: new Date()
                },
                // Use 1MB chunks for large files (default is 255KB)
                chunkSizeBytes: 1024 * 1024
            });

            let uploadedBytes = 0;
            let lastLoggedPercent = 0;
            let lastCallbackPercent = 0;

            uploadStream.on('error', (err) => {
                clearTimeout(timeoutId);
                console.error(`[GridFS] ❌ Upload error: ${err.message}`);
                reject(err);
            });

            uploadStream.on('finish', () => {
                clearTimeout(timeoutId);
                const duration = ((Date.now() - startTime) / 1000).toFixed(1);
                const speed = (totalSize / (1024 * 1024) / (duration / 1)).toFixed(2);
                console.log(`[GridFS] ✅ Upload complete: ${filename} (${totalSizeMB}MB) in ${duration}s (${speed}MB/s)`);
                resolve(uploadStream.id);
            });

            // Create a transform stream to track progress
            const progressStream = new stream.Transform({
                transform(chunk, encoding, callback) {
                    uploadedBytes += chunk.length;
                    const percent = Math.round((uploadedBytes / totalSize) * 100);
                    const uploadedMB = (uploadedBytes / (1024 * 1024)).toFixed(2);
                    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

                    // Log progress every 10%
                    if (percent >= lastLoggedPercent + 10) {
                        lastLoggedPercent = Math.floor(percent / 10) * 10;
                        console.log(`[GridFS] 📊 Upload progress: ${percent}% (${uploadedMB}/${totalSizeMB}MB) - ${elapsed}s elapsed`);
                    }

                    // Call progress callback every 5% (more frequent for DB updates)
                    if (onProgress && percent >= lastCallbackPercent + 5) {
                        lastCallbackPercent = Math.floor(percent / 5) * 5;
                        try {
                            onProgress({ percent, uploadedMB, totalMB: totalSizeMB, elapsed });
                        } catch (e) {
                            console.warn('[GridFS] Progress callback error:', e.message);
                        }
                    }

                    callback(null, chunk);
                }
            });

            // Create readable stream from buffer with smaller highWaterMark for better progress tracking
            const readableStream = new stream.Readable({
                highWaterMark: 256 * 1024 // 256KB chunks for progress tracking
            });

            // Push data in chunks for better progress reporting
            const CHUNK_SIZE = 256 * 1024; // 256KB
            let offset = 0;

            readableStream._read = function() {
                if (offset >= buffer.length) {
                    this.push(null);
                    return;
                }
                const chunk = buffer.slice(offset, offset + CHUNK_SIZE);
                offset += CHUNK_SIZE;
                this.push(chunk);
            };

            readableStream.pipe(progressStream).pipe(uploadStream);
        });
    }

    /**
     * Download a file from GridFS with progress logging
     * @param {ObjectId|String} fileId - File ID
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     * @param {Number} timeout - Timeout in ms (default: 3600000 = 1 hour)
     * @returns {Promise<Buffer>} - File data
     */
    async downloadFile(fileId, bucketName = 'zap_reports', timeout = 3600000) {
        const bucket = this.initialize(bucketName);

        // First get file metadata to know the size
        const files = await bucket
            .find({ _id: new mongoose.Types.ObjectId(fileId) })
            .toArray();

        const fileInfo = files[0];

        // Check if file exists
        if (!fileInfo) {
            console.error(`[GridFS] ❌ File not found: ${fileId} in bucket: ${bucketName}`);
            throw new Error(`File not found in GridFS: ${fileId}`);
        }

        const totalSize = fileInfo.length || 0;
        const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(2);
        const filename = fileInfo.filename || 'unknown';

        console.log(`[GridFS] 📥 Starting download: ${filename} (${totalSizeMB}MB) from bucket: ${bucketName}`);
        const startTime = Date.now();

        return new Promise((resolve, reject) => {
            // Dynamic timeout based on file size: 1 hour base + 1 min per 10MB
            const dynamicTimeout = Math.max(timeout, 3600000 + (totalSize / (10 * 1024 * 1024)) * 60000);

            const timeoutId = setTimeout(() => {
                reject(new Error(`GridFS download timeout after ${(dynamicTimeout/1000/60).toFixed(1)} minutes`));
            }, dynamicTimeout);

            const chunks = [];
            let downloadedBytes = 0;
            let lastLoggedPercent = 0;

            const downloadStream = bucket.openDownloadStream(
                new mongoose.Types.ObjectId(fileId)
            );

            downloadStream.on('data', chunk => {
                chunks.push(chunk);
                downloadedBytes += chunk.length;

                // Log progress every 10% for large files (>5MB)
                if (totalSize > 5 * 1024 * 1024) {
                    const percent = Math.round((downloadedBytes / totalSize) * 100);
                    if (percent >= lastLoggedPercent + 10) {
                        lastLoggedPercent = Math.floor(percent / 10) * 10;
                        const downloadedMB = (downloadedBytes / (1024 * 1024)).toFixed(2);
                        console.log(`[GridFS] 📊 Download progress: ${percent}% (${downloadedMB}/${totalSizeMB}MB)`);
                    }
                }
            });

            downloadStream.on('error', (err) => {
                clearTimeout(timeoutId);
                console.error(`[GridFS] ❌ Download error: ${err.message}`);
                reject(err);
            });

            downloadStream.on('end', () => {
                clearTimeout(timeoutId);
                const duration = ((Date.now() - startTime) / 1000).toFixed(1);
                const speed = totalSize > 0 ? (totalSize / (1024 * 1024) / (duration / 1)).toFixed(2) : 0;
                console.log(`[GridFS] ✅ Download complete: ${filename} (${totalSizeMB}MB) in ${duration}s (${speed}MB/s)`);
                resolve(Buffer.concat(chunks));
            });
        });
    }

    /**
     * Download file as stream (for large files)
     * @param {ObjectId|String} fileId - File ID
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     * @returns {ReadStream} - Download stream
     */
    downloadFileStream(fileId, bucketName = 'zap_reports') {
        const bucket = this.initialize(bucketName);
        return bucket.openDownloadStream(new mongoose.Types.ObjectId(fileId));
    }

    /**
     * Delete a file from GridFS
     * @param {ObjectId|String} fileId - File ID
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     */
    async deleteFile(fileId, bucketName = 'zap_reports') {
        const bucket = this.initialize(bucketName);
        await bucket.delete(new mongoose.Types.ObjectId(fileId));
    }

    /**
     * List files for a scan
     * @param {String} scanId - Scan ID
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     * @returns {Promise<Array>} - List of files
     */
    async listFiles(scanId, bucketName = 'zap_reports') {
        const bucket = this.initialize(bucketName);
        const files = await bucket
            .find({ 'metadata.scanId': scanId })
            .toArray();
        return files;
    }

    /**
     * Get file metadata
     * @param {ObjectId|String} fileId - File ID
     * @param {String} bucketName - Bucket name (default: 'zap_reports')
     */
    async getFileMetadata(fileId, bucketName = 'zap_reports') {
        const bucket = this.initialize(bucketName);
        const files = await bucket
            .find({ _id: new mongoose.Types.ObjectId(fileId) })
            .toArray();
        return files[0] || null;
    }
}

module.exports = new GridFSService();
