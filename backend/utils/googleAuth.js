// backend/utils/googleAuth.js
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/**
 * Verify a Google credential (access token or ID token) and return the
 * authenticated profile. Throws if neither token is provided or verification fails.
 */
async function verifyGoogleCredential({ token, googleAccessToken }) {
  let name, email, googleId, picture;

  if (googleAccessToken) {
    // Flow 1: Access Token (Custom Button)
    const response = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${googleAccessToken}` }
    });
    const data = response.data;
    name = data.name;
    email = data.email;
    googleId = data.sub;
    picture = data.picture;
  } else if (token) {
    // Flow 2: ID Token (Standard Button)
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    name = payload.name;
    email = payload.email;
    googleId = payload.sub;
    picture = payload.picture;
  } else {
    throw new Error('No token provided');
  }

  return { name, email, googleId, picture };
}

module.exports = { verifyGoogleCredential };
