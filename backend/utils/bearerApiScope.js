'use strict';

/**
 * Which hosts a form-login scan may carry the app's own Bearer token to, and
 * which of the URLs the app called may be replayed.
 *
 * The one place this policy lives. testLogin applies it to what the browser
 * saw, POST /test-login and the scheduler apply it again to testLogin's result,
 * and the scan worker applies it once more before anything reaches ZAP — the
 * same pure function each time, so the layers cannot drift apart.
 *
 * Rules:
 *  1. Token API hosts are only discovered for a site that does NOT sign in with
 *     a session cookie. A cookie site is scanned exactly as before Bearer
 *     support existed; whatever tokens its pages also send are ignored.
 *  2. A host run by a shared third-party API provider (payments, identity,
 *     BaaS, SaaS APIs, analytics, CDNs) is never a scan target, whatever token
 *     the app sends it: actively scanning it would attack someone else's
 *     multi-tenant service. Customer-owned hosting (`*.onrender.com`,
 *     `*.herokuapp.com`, `*.vercel.app`, API Gateway, Cloud Run…) stays
 *     eligible — that is the customer's own code.
 *  3. Host matching is label-boundary exact: `credit.villdesign.com.evil.net`
 *     is neither `credit.villdesign.com` nor one of its subdomains.
 *  4. A logout-shaped URL is never replayed (seed, session probe) and the
 *     scanner never attaches the token to one (see `bearerRuleRegex` in
 *     zapCredentialRules) — one replayed logout ends the session the scan
 *     depends on, and with server-side token revocation it cannot be renewed
 *     without logging in again.
 *
 * Nothing here logs, stores or returns a token anywhere but to its caller.
 */

const { checkScanTarget } = require('./scanTargetGuard');
const { ANALYTICS_HOST_PATTERN } = require('./loginRequestSignals');

const MAX_SEEDS_PER_ORIGIN = 50;
const BEARER_VALUE_PATTERN = /^Bearer\s+\S{8,}$/i;
// "Who am I" paths — the best probe for "is the token still good?".
const IDENTITY_PATH_PATTERN = /\/(me|whoami|profile|user|account|session|auth\/me|current[-_]?user)(\/|$|\?)/i;

/**
 * Path fragments of endpoints that end a session. Matched case-insensitively
 * anywhere in the path (camelCase `signOut`, `/auth/log-out`, `/logoff`,
 * `/tokens/revoke`, `/session/end`, `/sessions/destroy` …).
 * Kept as source text so the same list builds the Java regexes ZAP receives.
 */
const LOGOUT_PATH_FRAGMENTS = [
  'log[-_]?out', 'log[-_]?off', 'sign[-_]?out', 'sign[-_]?off',
  'revoke', 'invalidate', 'end[-_]?sessions?', 'sessions?[-_/]?end',
  'destroy[-_]?sessions?', 'sessions?[-_/]?destroy', 'terminate[-_]?sessions?'
];
const LOGOUT_PATH_PATTERN = new RegExp(`(?:${LOGOUT_PATH_FRAGMENTS.join('|')})`, 'i');

/**
 * Shared third-party API providers, as registrable domains. A host matches if it
 * IS one of these or is a subdomain of one (label boundary, see `hostMatchesDomain`).
 *
 * Deliberately absent (customer-owned compute, eligible): onrender.com,
 * herokuapp.com, vercel.app, netlify.app, fly.dev, railway.app, run.app,
 * cloudfunctions.net, appspot.com, azurewebsites.net, azure-api.net,
 * pages.dev, workers.dev, deno.dev, on.aws (Lambda URLs).
 */
const SHARED_API_PROVIDER_DOMAINS = [
  // Payments
  'stripe.com', 'stripe.network', 'paypal.com', 'paypalobjects.com', 'braintreegateway.com',
  'braintree-api.com', 'squareup.com', 'squareupsandbox.com', 'adyen.com', 'adyenpayments.com',
  'checkout.com', 'razorpay.com', 'pay.jp', 'komoju.com', 'paddle.com', 'lemonsqueezy.com',
  'gmo-pg.com', 'square.com', 'klarna.com', 'mollie.com',
  // Identity / auth-as-a-service
  'auth0.com', 'okta.com', 'oktapreview.com', 'okta-emea.com', 'oktacdn.com', 'onelogin.com',
  'clerk.com', 'clerk.dev', 'accounts.dev', 'stytch.com', 'workos.com', 'kinde.com', 'descope.com',
  'frontegg.com', 'magic.link', 'privy.io', 'pingone.com', 'pingidentity.com', 'duosecurity.com',
  'jumpcloud.com', 'fusionauth.io', 'logto.app', 'userfront.com', 'amazoncognito.com',
  'microsoftonline.com', 'b2clogin.com', 'live.com', 'microsoft.com',
  'windows.net', 'azure.com', 'office.com', 'office365.com', 'sharepoint.com',
  'apple.com', 'icloud.com',
  // Google (identitytoolkit / securetoken / firestore / storage / maps all live on googleapis.com)
  'googleapis.com', 'google.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com',
  'firebaseio.com', 'firebasedatabase.app',
  // Backend-as-a-service / hosted databases and realtime
  'supabase.co', 'supabase.com', 'supabase.in', 'supabase.io', 'appwrite.io', 'back4app.com',
  'convex.cloud', 'nhost.run', 'hasura.app', 'mongodb.com', 'mongodb.net', 'fauna.com',
  'pusher.com', 'pusherapp.com', 'ably.io', 'ably.com', 'pubnub.com', 'pubnub.net',
  'planetscale.com', 'neon.tech', 'upstash.io', 'turso.io', 'xata.sh',
  // Search, CMS, media
  'algolia.net', 'algolianet.com', 'algolia.io', 'typesense.net', 'contentful.com', 'ctfassets.net',
  'sanity.io', 'prismic.io', 'storyblok.com', 'datocms.com', 'hygraph.com', 'graphcms.com',
  'cloudinary.com', 'imgix.net', 'uploadcare.com', 'mux.com', 'vimeo.com',
  // SaaS / messaging / developer APIs
  'shopify.com', 'myshopify.com', 'salesforce.com', 'force.com', 'hubspot.com', 'hubapi.com',
  'zendesk.com', 'intercom.io', 'intercom.com', 'freshdesk.com', 'twilio.com', 'sendgrid.com',
  'sendgrid.net', 'mailgun.net', 'mailgun.com', 'mailchimp.com', 'postmarkapp.com', 'resend.com',
  'openai.com', 'anthropic.com', 'cohere.ai', 'cohere.com', 'mapbox.com', 'github.com',
  'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'atlassian.net', 'atlassian.com',
  'slack.com', 'discord.com', 'dropbox.com', 'dropboxapi.com', 'box.com', 'notion.so',
  'notion.com', 'airtable.com', 'onesignal.com', 'branch.io', 'split.io', 'statsig.com',
  'line.me', 'line-apps.com',
  // Social
  'facebook.com', 'facebook.net', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
  'tiktok.com',
  // Telemetry / error reporting (also in ANALYTICS_HOST_PATTERN; listed for completeness)
  'sentry.io', 'segment.io', 'segment.com', 'mixpanel.com', 'amplitude.com', 'datadoghq.com',
  'datadoghq.eu', 'newrelic.com', 'nr-data.net', 'bugsnag.com', 'launchdarkly.com',
  // CDNs, captchas, edge providers' own APIs
  'cloudflare.com', 'cloudflareinsights.com', 'cloudfront.net', 'akamaihd.net', 'akamaized.net',
  'fastly.net', 'jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'recaptcha.net', 'hcaptcha.com',
  'gravatar.com', 'wp.com', 'wordpress.com'
];

/**
 * AWS: every `*.amazonaws.com` host is a shared AWS service API (Cognito, STS,
 * S3, DynamoDB…) EXCEPT the shapes that are a customer's own endpoint.
 */
const AWS_CUSTOMER_ENDPOINT_PATTERNS = [
  /^[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/, // API Gateway
  /^[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$/, // AppSync GraphQL
  /\.elb\.(?:[a-z0-9-]+\.)?amazonaws\.com(\.cn)?$/,               // ALB / ELB
  /\.compute(?:-1)?\.amazonaws\.com(\.cn)?$/                       // EC2 public DNS
];

/** Lower-case, trailing dot and IPv6 brackets removed. '' if not a host. */
function normalizeHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
}

/**
 * True if `host` is `domain` or a subdomain of it — on a label boundary.
 * `credit.villdesign.com.evil.net` does not match `credit.villdesign.com`, and
 * `evilvilldesign.com` does not match `villdesign.com`.
 */
function hostMatchesDomain(host, domain) {
  const h = normalizeHost(host);
  const d = normalizeHost(domain);
  if (!h || !d) return false;
  return h === d || h.endsWith(`.${d}`);
}

/** A host operated by a shared third-party API provider (never scanned). */
function isSharedThirdPartyApiHost(host) {
  const h = normalizeHost(host);
  if (!h) return true;
  if (ANALYTICS_HOST_PATTERN.test(h)) return true;
  if (SHARED_API_PROVIDER_DOMAINS.some(d => hostMatchesDomain(h, d))) return true;
  if (hostMatchesDomain(h, 'amazonaws.com') || hostMatchesDomain(h, 'amazonaws.com.cn')) {
    return !AWS_CUSTOMER_ENDPOINT_PATTERNS.some(p => p.test(h));
  }
  return false;
}

/** The URL's path ends a session (logout, sign-out, revoke…). Unparseable → true. */
function isLogoutUrl(url) {
  try {
    return LOGOUT_PATH_PATTERN.test(decodeURIComponent(new URL(url).pathname));
  } catch {
    try { return LOGOUT_PATH_PATTERN.test(new URL(url).pathname); } catch { return true; }
  }
}

/** Canonical http(s) origin of a URL, or null. */
function originOf(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * Why an API origin may not receive the token, or null if it may.
 * @returns {null|'invalid_origin'|'refused_target'|'shared_third_party'}
 */
function apiOriginRefusal(origin) {
  const canonical = originOf(origin);
  if (!canonical || canonical !== String(origin)) return 'invalid_origin';
  if (!checkScanTarget(canonical).ok) return 'refused_target';
  if (isSharedThirdPartyApiHost(new URL(canonical).hostname)) return 'shared_third_party';
  return null;
}

/**
 * Filter Bearer sessions down to what the scan may use.
 *
 * @param {Array<{origin:string, authorization:string, seedUrls?:string[], verifyUrl?:string|null}>} sessions
 * @param {{hasSessionCookie?: boolean}} [opts] hasSessionCookie: the login set a
 *   session cookie — then no token host is used at all (rule 1).
 * @returns {Array<{origin:string, authorization:string, seedUrls:string[], verifyUrl:string|null}>}
 *   New objects; seeds are same-origin GET URLs, never logout-shaped, at most 50.
 */
function eligibleBearerSessions(sessions, { hasSessionCookie = false } = {}) {
  if (hasSessionCookie) return [];
  const out = [];
  const seen = new Set();
  for (const s of Array.isArray(sessions) ? sessions : []) {
    if (!s || typeof s.origin !== 'string' || typeof s.authorization !== 'string') continue;
    const authorization = s.authorization.trim();
    if (!BEARER_VALUE_PATTERN.test(authorization)) continue;
    if (apiOriginRefusal(s.origin) !== null) continue;
    if (seen.has(s.origin)) continue;
    seen.add(s.origin);

    const seedUrls = [];
    for (const url of Array.isArray(s.seedUrls) ? s.seedUrls : []) {
      if (seedUrls.length >= MAX_SEEDS_PER_ORIGIN) break;
      if (typeof url !== 'string' || originOf(url) !== s.origin) continue;
      if (isLogoutUrl(url) || !checkScanTarget(url).ok || seedUrls.includes(url)) continue;
      seedUrls.push(url);
    }
    // The probe is replayed throughout the scan: it must be one of the vetted
    // seeds (never a logout URL, never another origin).
    let verifyUrl = typeof s.verifyUrl === 'string' && seedUrls.includes(s.verifyUrl) ? s.verifyUrl : null;
    if (!verifyUrl) {
      verifyUrl = seedUrls.find(u => IDENTITY_PATH_PATTERN.test(new URL(u).pathname)) || seedUrls[0] || null;
    }
    out.push({ origin: s.origin, authorization, seedUrls, verifyUrl });
  }
  return out;
}

module.exports = {
  MAX_SEEDS_PER_ORIGIN,
  IDENTITY_PATH_PATTERN,
  LOGOUT_PATH_FRAGMENTS,
  LOGOUT_PATH_PATTERN,
  SHARED_API_PROVIDER_DOMAINS,
  normalizeHost,
  hostMatchesDomain,
  isSharedThirdPartyApiHost,
  isLogoutUrl,
  apiOriginRefusal,
  eligibleBearerSessions
};
