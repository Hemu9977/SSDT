// FRONTEND_URL may be a comma-separated list of domains (see server.js CORS);
// links sent to users always use the first entry.
const getFrontendBaseUrl = () =>
  (process.env.FRONTEND_URL || 'http://localhost:3000').split(',')[0].trim();

module.exports = { getFrontendBaseUrl };
