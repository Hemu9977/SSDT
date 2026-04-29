// Single source of truth for the backend API base URL.
// Set REACT_APP_API_URL in your .env (dev) or as a build-time env var (CI/CD) to point
// at the ALB DNS or your custom domain. Falls back to localhost for local dev.
export const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001';
