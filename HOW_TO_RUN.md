# HOW TO RUN SSDT (Security Scan & Detection Tool)

## Prerequisites

- **Node.js** v18+ and npm v9+
- **Docker Desktop** (with Docker Compose)
- **Python 3.x** (for ZAP scanner scripts)
- **MongoDB Atlas** account with a cluster (local MongoDB is not supported)

---

## 1. Clone the Repository

```bash
git clone https://github.com/your-repo/SSDT.git
cd SSDT
```

---

## 2. Environment Setup

### Backend (.env)

Create `backend/.env` with the following variables:

```env
# MongoDB Atlas (required — local MongoDB is not supported)
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/virustotal-scanner?retryWrites=true&w=majority

# JWT Secret (generate a random string)
JWT_SECRET=your-super-secret-jwt-key-here

# Google PageSpeed API Key
PAGESPEED_API_KEY=your-pagespeed-api-key

# Gemini AI API Keys (for AI reports)
GEMINI_API_KEY=your-gemini-api-key
GEMINI_API_KEY_2=optional-backup-key
GEMINI_API_KEY_3=optional-backup-key

# Email (Gmail with App Password)
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-16-char-app-password

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# URLScan.io API Key
URLSCAN_API_KEY=your-urlscan-api-key

# WebCheck Service URL
WEBCHECK_URI=http://localhost:3002

# Rate Limiting (set to false for development)
RATE_LIMIT_ENABLED=false
```

### Frontend (.env)

Create `frontend/.env`:

```env
REACT_APP_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

---

## 3. Start Docker Containers

### Start ZAP Scanner and WebCheck

```bash
cd SSDT

# Stop any existing containers
docker-compose down

# Remove old ZAP container if exists
docker stop zap-scanner 2>/dev/null
docker rm zap-scanner 2>/dev/null

# Start all containers (builds WebCheck if needed)
docker-compose up -d --build
```

### Verify Containers are Running

```bash
docker ps
```

You should see:
- `zap-scanner` - OWASP ZAP on port 8080
- `ssdt-webcheck` - WebCheck service on port 3002

---

## 4. Install Dependencies

### Backend

```bash
cd backend
npm install
```

### Frontend

```bash
cd frontend
npm install
```

---

## 5. Start the Application

### Terminal 1: Backend (Port 3001)

```bash
cd backend
npm run dev
```

### Terminal 2: Frontend (Port 3000)

```bash
cd frontend
npm start
```

---

## 6. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001
- **ZAP API**: http://localhost:8080
- **WebCheck API**: http://localhost:3002

---

## 7. Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID (Web Application)
3. Add Authorized JavaScript origins: `http://localhost:3000`
4. Add Authorized redirect URIs: `http://localhost:3000`
5. Copy Client ID to both `backend/.env` and `frontend/.env`

---

## 8. Gmail App Password Setup

1. Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
2. Create a new app password (name: SSDT)
3. Copy the 16-character password to `backend/.env` as `EMAIL_PASSWORD`

---

## Troubleshooting

### ZAP Container Name Conflict

```bash
docker stop zap-scanner
docker rm zap-scanner
docker-compose up -d
```

### WebCheck Not Responding

```bash
docker-compose down
docker-compose up -d --build
```

### Backend Keeps Restarting During Scans

The `nodemon.json` in backend should ignore ZAP report files. If missing:

```json
{
  "watch": ["*.js", "routes/", "services/", "models/", "middleware/"],
  "ignore": ["zap-report*", "*.log", "reports/"]
}
```

### MongoDB Connection Failed

Make sure MongoDB is running locally or update `MONGODB_URI` to your MongoDB Atlas connection string.

---

## Quick Start Commands

```bash
# 1. Start Docker containers
docker-compose up -d

# 2. Start Backend (Terminal 1)
cd backend && npm run dev

# 3. Start Frontend (Terminal 2)
cd frontend && npm start

# 4. Open browser
# http://localhost:3000
```

---

## API Keys Required

| Service | Get Key From |
|---------|--------------|
| Google PageSpeed | https://console.cloud.google.com/apis/credentials |
| Gemini AI | https://aistudio.google.com/app/apikey |
| URLScan.io | https://urlscan.io/user/profile |
| Google OAuth | https://console.cloud.google.com/apis/credentials |

---

## Ports Summary

| Service | Port |
|---------|------|
| Frontend (React) | 3000 |
| Backend (Express) | 3001 |
| WebCheck | 3002 |
| ZAP Scanner | 8080 |
| MongoDB | 27017 |
