# Enhanced ZAP Scanner Integration Guide

## Overview
This guide will help you integrate the maximum performance ZAP scanner into your SSDT backend.

---

## Step 1: Deploy Python Scanner Script

### 1.1 Create Scripts Directory
```bash
cd backend
mkdir -p scripts
```

### 1.2 Copy Python Scanner
Copy `zap_ai_scanner.py` to `backend/scripts/`:

```bash
# From the directory where you have zap_ai_scanner.py
cp zap_ai_scanner.py backend/scripts/
chmod +x backend/scripts/zap_ai_scanner.py
```

### 1.3 Verify Python Dependencies
The script requires Python 3 and `requests` library:

```bash
# Check Python version
python3 --version

# Install requests if needed
pip3 install requests --break-system-packages
```

---

## Step 2: Replace Service and Routes Files

### 2.1 Backup Current Files
```bash
cd backend
cp services/zapService.js services/zapService.js.backup
cp routes/zapRoutes.js routes/zapRoutes.js.backup
```

### 2.2 Replace with Enhanced Versions
```bash
# Replace zapService.js
cp /path/to/enhanced_zapService.js services/zapService.js

# Replace zapRoutes.js
cp /path/to/enhanced_zapRoutes.js routes/zapRoutes.js
```

---

## Step 3: Update Environment Variables

Add these to your `backend/.env`:

```env
# ZAP Configuration (already exists in your .env.example)
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=<your own random key: openssl rand -hex 32>
```

---

## Step 4: Ensure ZAP Docker Container is Running

### 4.1 Start ZAP with Optimal Settings
```bash
docker run -d --name zap-scanner \
  -p 8080:8080 \
  --memory=8g \
  --memory-swap=10g \
  --cpus=4 \
  zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true \
  -config spider.maxDepth=20 \
  -config spider.maxDuration=120 \
  -config spider.threadCount=10 \
  -config scanner.threadPerHost=10 \
  -config scanner.hostPerScan=10
```

📊 **MEMORY ALLOCATION:**
- RAM: 8GB (handles scans up to 15,000 URLs)
- Swap: 10GB (prevents crashes)
- CPUs: 4 cores (optimal parallelization)

For larger scans (>15K URLs), increase to --memory=10g or --memory=12g

### 4.2 Wait for ZAP to Start (60 seconds)
```bash
echo "Waiting for ZAP to initialize..."
sleep 60

# Test ZAP is ready
curl http://localhost:8080/JSON/core/view/version/
```

---

## Step 5: Update Server.js (Already Done!)

Your `server.js` already has ZAP routes registered:
```javascript
app.use('/api/zap', apiLimiter, scanLimiter, zapRoutes);
```

No changes needed here!

---

## Step 6: Restart Backend Server

```bash
# If using npm
npm run dev

# If using node directly
node server.js
```

---

## Step 7: Test the Integration

### 7.1 Check ZAP Health
```bash
curl http://localhost:3001/api/zap/health
```

Expected response:
```json
{
  "success": true,
  "status": "healthy",
  "version": "2.XX.X",
  "message": "ZAP service is running and accessible"
}
```

### 7.2 Get Scanner Info
```bash
curl http://localhost:3001/api/zap/info
```

### 7.3 Start a Test Scan (Requires Authentication)

First, login and get your token:
```bash
# Login
TOKEN=$(curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}' \
  | jq -r '.token')

# Start scan
curl -X POST http://localhost:3001/api/zap/scan \
  -H "Content-Type: application/json" \
  -H "x-auth-token: $TOKEN" \
  -d '{"url":"https://example.com","quickMode":true}'
```

Expected response:
```json
{
  "success": true,
  "message": "ZAP scan initiated",
  "scanId": "zap-1736089234567-abc123",
  "analysisId": "zap-1736089234567-abc123",
  "target": "https://example.com",
  "scanMode": "quick",
  "estimatedTime": "5-15 minutes",
  "note": "Poll /api/zap/status/:scanId for progress updates"
}
```

### 7.4 Check Scan Status
```bash
SCAN_ID="zap-1736089234567-abc123"  # Replace with your actual scan ID

curl http://localhost:3001/api/zap/status/$SCAN_ID \
  -H "x-auth-token: $TOKEN"
```

---

## API Endpoints Reference

### 1. Health Check (Public)
```
GET /api/zap/health
```
Returns ZAP service health status.

### 2. Scanner Information (Public)
```
GET /api/zap/info
```
Returns scanner capabilities and documentation.

### 3. Start Scan (Protected + Rate Limited)
```
POST /api/zap/scan
Headers: x-auth-token: <jwt_token>
Body: {
  "url": "https://target.com",
  "quickMode": false  // optional, default false
}
```

### 4. Check Scan Status (Protected)
```
GET /api/zap/status/:scanId
Headers: x-auth-token: <jwt_token>
```

### 5. Scan History (Protected)
```
GET /api/zap/scans
Headers: x-auth-token: <jwt_token>
```

---

## Understanding Scan Results

### Status Values
- `queued` - Scan is queued
- `pending` - Scan is running
- `completed` - Scan finished successfully
- `failed` - Scan encountered an error

### Phases
1. **spider** - Traditional spider crawling static links
2. **ajax-spider** - JavaScript execution for dynamic content
3. **passive-scan** - Analyzing proxied traffic
4. **active-scan** - Active vulnerability testing
5. **generating-reports** - Finalizing results

### Sample Status Response
```json
{
  "success": true,
  "scanId": "zap-1736089234567-abc123",
  "status": "completed",
  "target": "https://example.com",
  "zapResult": {
    "status": "completed",
    "phase": "generating-reports",
    "urlsFound": 247,
    "alerts": 12,
    "progress": 100,
    "breakdown": {
      "High": 2,
      "Medium": 4,
      "Low": 5,
      "Informational": 1
    },
    "completedAt": "2026-01-05T12:34:56.789Z"
  }
}
```

---

## Troubleshooting

### Problem: "ZAP service is not available"
**Solution:**
1. Check if ZAP container is running:
   ```bash
   docker ps | grep zap
   ```
2. Verify ZAP is accessible:
   ```bash
   curl http://localhost:8080/JSON/core/view/version/
   ```
3. Check Docker logs:
   ```bash
   docker logs zap-scanner
   ```

### Problem: "Python3 not found"
**Solution:**
```bash
# Install Python 3
sudo apt update
sudo apt install python3 python3-pip

# Verify installation
python3 --version
```

### Problem: "ZAP scanner script not found"
**Solution:**
```bash
# Ensure script is in correct location
ls -la backend/scripts/zap_ai_scanner.py

# If missing, copy from outputs
cp zap_ai_scanner.py backend/scripts/
chmod +x backend/scripts/zap_ai_scanner.py
```

### Problem: "Scan takes too long"
**Solution:**
- Use `quickMode: true` for faster scans
- Target has many URLs (expected behavior)
- Check if target has bot protection

### Problem: "Low URL discovery"
**Diagnosis:**
- Target blocks automated scanning
- Target is mostly static with few links
- Robots.txt blocking

**Solution:**
- Verify you have permission to scan the target
- Check target is accessible
- Try different target for testing

---

## Performance Tuning

### Quick Scan Mode
Best for: Initial testing, CI/CD pipelines
```javascript
{ "url": "https://target.com", "quickMode": true }
```
- Depth: 10
- Duration: 30-60 seconds per phase
- Estimated time: 5-15 minutes

### Full Scan Mode (Default)
Best for: Comprehensive security audits
```javascript
{ "url": "https://target.com", "quickMode": false }
```
- Depth: 20
- Duration: 120 seconds per phase
- Estimated time: 15-60 minutes

### Docker Resource Allocation
For better performance, increase Docker resources:
```bash
docker update zap-scanner --memory=8g --cpus=4
```

---

## Rate Limiting

Current rate limits (from rateLimiter.js):
- **Scan Rate Limiter**: 20 scans per 10 minutes per user
- **API Rate Limiter**: 100 requests per 15 minutes per user

To adjust for development:
```env
# In .env
SCAN_RATE_LIMIT_MAX=100
SCAN_RATE_LIMIT_WINDOW_MS=600000
```

---

## Frontend Integration Example

```javascript
// Start scan
const startScan = async (url) => {
  const response = await fetch('http://localhost:3001/api/zap/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-auth-token': localStorage.getItem('token')
    },
    body: JSON.stringify({ url, quickMode: false })
  });
  
  const data = await response.json();
  return data.scanId;
};

// Poll for status
const pollScanStatus = async (scanId) => {
  const interval = setInterval(async () => {
    const response = await fetch(`http://localhost:3001/api/zap/status/${scanId}`, {
      headers: {
        'x-auth-token': localStorage.getItem('token')
      }
    });
    
    const data = await response.json();
    
    // Update UI with progress
    updateUI(data);
    
    // Stop polling when complete
    if (data.status === 'completed' || data.status === 'failed') {
      clearInterval(interval);
      showResults(data);
    }
  }, 5000); // Poll every 5 seconds
};
```

---

## Security Notes

1. **Authentication Required**: All scan endpoints (except health/info) require valid JWT token
2. **Rate Limiting**: Prevents abuse with per-user limits
3. **User Isolation**: Users can only access their own scans
4. **URL Validation**: Prevents scanning of localhost/private IPs
5. **MongoDB Storage**: All scans are tracked and auditable

---

## Success Checklist

- [ ] Python script deployed to `backend/scripts/zap_ai_scanner.py`
- [ ] Python 3 and requests library installed
- [ ] ZAP Docker container running on port 8080
- [ ] Enhanced service and routes files replaced
- [ ] Backend server restarted
- [ ] Health check returns healthy status
- [ ] Test scan initiated successfully
- [ ] Scan results retrieved successfully

---

## Next Steps

1. **Frontend Integration**: Create UI components for ZAP scanning
2. **Result Visualization**: Display scan results with charts/graphs
3. **Notifications**: Add email/webhook notifications for completed scans
4. **Scheduling**: Add ability to schedule recurring scans
5. **Comparison**: Compare results between different scans

---

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review backend logs: `docker logs <backend_container>`
3. Review ZAP logs: `docker logs zap-scanner`
4. Ensure all dependencies are installed correctly

The system is now ready for comprehensive, maximum-performance web application security scanning!
