// backend/utils/googleAuth.js
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');

const TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo';
const USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';
const GOOGLE_TIMEOUT_MS = 10000;

// The production task definition supplies the client id to the backend as
// REACT_APP_GOOGLE_CLIENT_ID (the same secret the frontend build uses), not as
// GOOGLE_CLIENT_ID. Accept either; with neither, Google sign-in is refused
// rather than accepting a token issued to an unknown audience.
const configuredClientId = () =>
  process.env.GOOGLE_CLIENT_ID || process.env.REACT_APP_GOOGLE_CLIENT_ID || null;

// A web client id looks like `<project-number>-<hash>.apps.googleusercontent.com`.
// The client SECRET (`GOCSPX-…`) sits next to it in Cloud Console and has been
// pasted into the client-id variable before; every token then fails `audience`
// with nothing in the logs saying why. Only the id is public, so only a value of
// the id's shape is ever logged.
const CLIENT_ID_RE = /^[\w-]+\.apps\.googleusercontent\.com$/;
const describeMisconfiguredId = (value) =>
  /^GOCSPX-/.test(value)
    ? 'holds an OAuth client SECRET (GOCSPX-…), not a client id — rotate that secret and set the web client id'
    : 'is not a Google OAuth web client id (<number>-<hash>.apps.googleusercontent.com)';

let idTokenClient = null;
let idTokenClientId = null;
const getIdTokenClient = (clientId) => {
  if (!idTokenClient || idTokenClientId !== clientId) {
    idTokenClient = new OAuth2Client(clientId);
    idTokenClientId = clientId;
  }
  return idTokenClient;
};

class GoogleCredentialError extends Error {
  constructor(reason) {
    super(`Google credential rejected: ${reason}`);
    this.name = 'GoogleCredentialError';
    this.reason = reason;
  }
}

// tokeninfo returns email_verified as the string "true"; ID-token payloads as a boolean.
const isVerifiedFlag = (v) => v === true || v === 'true';

/**
 * Verify a Google credential (access token or ID token) and return the
 * authenticated profile. Throws if neither token is provided or verification fails.
 *
 * An access token is only proof of identity when it was issued to THIS app.
 * `userinfo` answers for a token minted for any Google OAuth client, so a token
 * a user once granted to some other site could otherwise be replayed here to
 * sign in as them. tokeninfo reports the token's audience, which must be ours.
 * Both flows also require Google to have verified the email address, because
 * accounts are matched (and linked) by email.
 */
async function verifyGoogleCredential({ token, googleAccessToken }) {
  const clientId = configuredClientId();
  if (!clientId) {
    console.error('❌ [googleAuth] GOOGLE_CLIENT_ID / REACT_APP_GOOGLE_CLIENT_ID is not set — Google sign-in refused');
    throw new GoogleCredentialError('not_configured');
  }
  if (!CLIENT_ID_RE.test(clientId)) {
    const source = process.env.GOOGLE_CLIENT_ID ? 'GOOGLE_CLIENT_ID' : 'REACT_APP_GOOGLE_CLIENT_ID';
    console.error(`❌ [googleAuth] ${source} ${describeMisconfiguredId(clientId)} — Google sign-in refused`);
    throw new GoogleCredentialError('misconfigured');
  }

  if (googleAccessToken) {
    // Flow 1: Access Token (Custom Button)
    const { data: info } = await axios.get(TOKENINFO_URL, {
      params: { access_token: googleAccessToken },
      timeout: GOOGLE_TIMEOUT_MS,
    });
    if (info.aud !== clientId && info.azp !== clientId) {
      // Both are public client ids. Seeing them side by side tells a frontend /
      // backend client-id mismatch apart from a token minted for some other app.
      console.warn(`[googleAuth] audience mismatch: token aud=${info.aud} azp=${info.azp}, expected ${clientId}`);
      throw new GoogleCredentialError('audience');
    }
    if (!info.sub || !info.email) throw new GoogleCredentialError('profile');
    if (!isVerifiedFlag(info.email_verified)) throw new GoogleCredentialError('email_unverified');

    // Name and picture are not in tokeninfo. The identity (sub, email) is taken
    // from tokeninfo; userinfo must describe the same account.
    const { data: profile } = await axios.get(USERINFO_URL, {
      headers: { Authorization: `Bearer ${googleAccessToken}` },
      timeout: GOOGLE_TIMEOUT_MS,
    });
    if (profile.sub !== info.sub) throw new GoogleCredentialError('subject_mismatch');

    return { name: profile.name, email: info.email, googleId: info.sub, picture: profile.picture };
  }

  if (token) {
    // Flow 2: ID Token (Standard Button)
    const ticket = await getIdTokenClient(clientId).verifyIdToken({ idToken: token, audience: clientId });
    const payload = ticket.getPayload();
    if (!payload || !payload.sub || !payload.email) throw new GoogleCredentialError('profile');
    if (!isVerifiedFlag(payload.email_verified)) throw new GoogleCredentialError('email_unverified');
    return { name: payload.name, email: payload.email, googleId: payload.sub, picture: payload.picture };
  }

  throw new Error('No token provided');
}

module.exports = { verifyGoogleCredential, GoogleCredentialError };
