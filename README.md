# SSDT - Security Scanning & Detection Tool

A comprehensive web security and performance analysis tool that scans URLs for malware, performance issues, security configuration problems, and **active vulnerabilities**.

## Features

### Combined URL Scanning

Scan any URL and get a complete analysis in one request:

1. **PageSpeed Insights** - Performance, Accessibility, Best Practices, SEO scores
2. **Mozilla Observatory** - Security configuration and headers analysis
3. **OWASP ZAP** - Real-time Active Scanning (DAST) for vulnerabilities like SQL Injection, XSS, and more.
4. **WebCheck** - 29 sub-scans (SSL, DNS, headers, cookies, tech stack, ports, etc.)
5. **urlscan.io** - Screenshot + page analysis
6. **AI Analysis** - Gemini-powered comprehensive security & performance report

### User Authentication

- Google Login & Sign up - Seamless authentication using Google OAuth 2.0
- User registration with email verification
- OTP-based login for enhanced security
- JWT token authentication
- Forgot password with email reset link
- Password reset with secure token validation
- Skip OTP for recently reset passwords (24-hour window)
- Inline UI messages instead of browser alerts

### Multi-language Support

- English and Japanese translation support
- Google Translate API integration

## Tech Stack

### Infrastructure
- **Docker** - Used exclusively for OWASP ZAP scanner (isolated security scanning)
- **Node.js** - Backend and Frontend run natively

### Backend
- Node.js + Express
- MongoDB (Mongoose)
- Google Auth Library (OAuth 2.0)
- **APIs:**
  - Google PageSpeed Insights API
  - Mozilla Observatory API v2
  - OWASP ZAP API (Docker Container)
  - WebCheck API (Docker Container)
  - urlscan.io API
  - Google Gemini AI
  - Google Translate API

### Frontend
- React 19
- React Router
- Google OAuth (@react-oauth/google)
- SCSS styling
- Responsive design

## Project Structure

```
SSDT/
├── docker-compose.yml         # OWASP ZAP container only
├── backend/
│   ├── middleware/            # Auth, rate limiting
│   ├── models/                # MongoDB schemas
│   ├── routes/                # API endpoints (includes zapRoutes)
│   ├── services/              # Logic (PSI, ZAP, WebCheck, Gemini)
│   └── server.js              # Express server
├── frontend/
│   ├── src/
│   └── ...
└── README.md
```

## Setup & Installation

### Prerequisites

- Node.js >= 18.0.0
- Docker Desktop (for OWASP ZAP scanner only)
- MongoDB Atlas account or local MongoDB
- API Keys (see `.env.example`)

### Installation Steps

1. **Clone and install dependencies:**

   ```bash
   git clone https://github.com/yourusername/ssdt.git
   cd ssdt

   # Backend
   cd backend
   npm install

   # Frontend
   cd ../frontend
   npm install
   ```

2. **Configure environment variables:**

   ```bash
   # Backend
   cd backend
   cp .env.example .env
   # Edit .env with your API keys
   ```

   ```bash
   # Frontend
   cd frontend
   cp .env.example .env
   # Edit .env with your Google Client ID
   ```

3. **Start the OWASP ZAP Docker container:**

   ```bash
   # From the project root
   docker-compose up -d
   ```

   This starts only the ZAP scanner container. Verify it's running:
   ```bash
   docker ps
   # Should show: zap-daemon running on port 8080
   ```

4. **Start the application:**

   ```bash
   # Terminal 1 - Backend
   cd backend
   npm run dev

   # Terminal 2 - Frontend
   cd frontend
   npm start
   ```

5. **Access the app:**

   - Frontend: http://localhost:3000
   - Backend: http://localhost:3001
   - ZAP Interface: http://localhost:8080 (verify scanner is running)

   **IMPORTANT**: Make sure the backend is running BEFORE accessing the frontend to avoid "Failed to fetch" errors.

## Usage

1. Register:
   - Use Sign up with Google for instant access.
   - OR Register manually with email/password and verify via OTP.
2. Login with OTP verification (or directly if password was recently reset)
3. Enter a URL to scan (e.g., https://github.com)
4. Wait 30-60 seconds for complete analysis
5. View results:
   - Performance scores (4 metrics)
   - Security configuration grade from Observatory
   - OWASP ZAP vulnerability findings
   - WebCheck analysis (SSL, DNS, headers, tech stack, etc.)
   - urlscan.io screenshot and page analysis
   - AI-generated comprehensive analysis

## API Endpoints

### ZAP Scanning

- `POST /api/zap/scan` - Trigger a real-time active scan against a target URL.

### Authentication

- `POST /auth/google` - Login or Register with Google (Access Token flow)
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and send OTP (skips OTP for recently reset passwords)
- `POST /auth/verify-otp` - Verify OTP and get JWT token
- `POST /auth/resend-otp` - Resend OTP
- `POST /auth/forgot-password` - Send password reset email
- `POST /auth/reset-password` - Reset password with token
- `GET /auth/me` - Get current user (protected)

### Standard Scanning

- `POST /api/scan/combined-url-scan` - Initiate combined scan (PSI + Observatory + ZAP + WebCheck + urlscan + AI)
- `GET /api/scan/active-scan` - Poll for the caller's in-flight scan
- `GET /api/scan/combined-analysis/:id` - Fetch scan results
- `GET /api/scan/scan/:analysisId` - Load a historical scan
  (`virustotalRoutes.js` is mounted at `/api/scan` in `server.js` — the filename
  is legacy, the `/api/vt` prefix is not and never was a real mount.)
- `GET|POST|PATCH|DELETE /api/admin/*` - Platform admin API (requires `systemRole`
  of `admin` or `superadmin`; see CLAUDE.md for the bootstrap steps)

### Translation

- `POST /api/translate` - Translate text (protected)

## Environment Variables

Required in `backend/.env`:

```bash
# MongoDB
MONGO_URI=your_mongodb_connection_string

# Authentication
JWT_SECRET=your_jwt_secret

# APIs
PSI_API_KEY=your_pagespeed_api_key

# Gemini API Keys (with fallback support)
GEMINI_API_KEY=your_gemini_api_key
GEMINI_API_KEY_2=your_second_gemini_api_key  # Optional fallback
GEMINI_API_KEY_3=your_third_gemini_api_key   # Optional fallback

# Email (for OTP)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password

# OWASP ZAP Configuration (Docker container)
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=ssdt-secure-zap-2025

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id_from_cloud_console

# Server
PORT=3001
NODE_ENV=development
```

Required in `frontend/.env`:

```bash
# Google OAuth Client ID for frontend authentication
REACT_APP_GOOGLE_CLIENT_ID=your_google_client_id_here
```

### Multiple Gemini API Keys (Recommended)

To avoid rate limiting and "model overloaded" errors, you can configure multiple Gemini API keys:

1. **Get multiple API keys** from [Google AI Studio](https://aistudio.google.com/app/apikey)
2. **Add them to your `.env`** file:

   ```bash
   GEMINI_API_KEY=your_first_key
   GEMINI_API_KEY_2=your_second_key
   GEMINI_API_KEY_3=your_third_key
   ```

3. **How it works:**
   - The system automatically tries keys in order
   - If one key is overloaded/rate-limited, it switches to the next
   - 500ms delay between fallback attempts

## Rate Limiting & Security

- **Combined Rate Limiter:** Respects external API limits.
- **ZAP Throttling:** Active scans are resource-intensive; backend queues ensure stability.
- **Docker Isolation:** ZAP runs in a restricted container with regex-based API access control.
- Auth endpoints: 10 requests per 15 minutes
- API endpoints: 100 requests per 15 minutes
- Scan endpoints: 5 scans per 15 minutes per user

## Security Features

- JWT-based authentication
- OTP email verification
- Rate limiting on all endpoints
- Input validation
- CORS protection
- Secure password hashing (bcrypt)

## Development

```bash
# Start ZAP container (required for security scans)
docker-compose up -d

# Backend (with auto-reload)
cd backend
npm run dev

# Frontend (with hot-reload)
cd frontend
npm start

# Build frontend for production
cd frontend
npm run build
```

## Troubleshooting

**ZAP Connection Failed:**

- Ensure the Docker container `zap-daemon` is running (`docker ps`).
- Check if `ZAP_API_KEY` in `.env` matches the key in `docker-compose.yml` (default: `ssdt-secure-zap-2025`).

**Ports Not Available:**

- Stop any processes running on ports 3000, 3001, or 8080 before starting the application.

## License

ISC

## Important commands to run the code

```bash
npm install --save-dev nodemon
npm install express mongoose bcryptjs jsonwebtoken cookie-parser dotenv cors
```
