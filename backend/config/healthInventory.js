/**
 * backend/config/healthInventory.js
 *
 * The services the admin System Health page reports on — the only place that
 * list is defined. The frontend renders whatever ids the API returns and keeps
 * nothing but a label and icon per id; it cannot add, remove or point a check
 * at a different resource.
 *
 * A service is listed because its production role is established (task
 * definition, call sites, docs/ADMIN_DASHBOARD_AUDIT.md §3.3), not because its
 * code or a credential exists. Candidates that were considered and left out are
 * in EXCLUDED below, with the reason, so the decision is reviewable.
 *
 * Statuses (the same meaning for every service):
 *   healthy     a live check succeeded within its thresholds
 *   degraded    reachable, but impaired (slow, partial failure, alarm firing,
 *               fewer tasks than desired, most recent uses failing)
 *   unavailable the check reached a definite failure: refused, timed out,
 *               rejected the credentials, or required configuration is missing
 *   starting    scaled from zero on demand and not serving yet (scale-to-zero only)
 *   idle        intentionally doing nothing: scaled to zero, or no work queued.
 *               Not a fault
 *   configured  configuration is present but nothing has exercised it, and a
 *               live check would spend paid quota. Never counted as healthy
 *   unknown     the status could not be determined: the monitoring call itself
 *               failed (e.g. AWS permission missing) or nothing to measure yet
 *
 * `critical` services are the ones without which no scan or sign-in works; one
 * of them unavailable makes the overall state "outage".
 *
 * `basis` says what a status rests on, so the page can say so:
 *   live_probe       a request to the service made by this health check
 *   process          measured in this backend process
 *   aws_api          read from an AWS API (ECS, ELB, CloudWatch, SES)
 *   credential_check credentials exchanged for a token; no billable call
 *
 * `cacheTtlMs` (third-party APIs with a quota): how long a healthy result is
 * reused; failures are re-checked after at most a minute (services/systemHealth.js).
 *   recent_activity  outcomes of real customer scans in the window
 *   app_signal       outcomes this backend task recorded since it started
 */

const INVENTORY = [
  {
    id: 'api',
    category: 'core',
    role: 'required',
    critical: true,
    basis: 'process',
    timeoutMs: 1500,
    onTimeout: 'unknown',
    purpose: 'The Express API on ECS that serves every customer and admin request.',
    rationale: 'Shows which release is running and whether this task is overloaded.',
    method: 'Event-loop delay (p99) and heap use measured in this process; ECS task metadata for the task-definition revision.',
    thresholds: { eventLoopP99Ms: 200, heapUsedRatio: 0.85 },
  },
  {
    id: 'mongodb',
    category: 'core',
    role: 'required',
    critical: true,
    basis: 'live_probe',
    timeoutMs: 3000,
    onTimeout: 'unavailable',
    purpose: 'Primary database: users, organizations, scans, billing state, audit log.',
    rationale: 'Every request depends on it.',
    method: 'Read-only `ping` command on the existing connection.',
    thresholds: { degradedLatencyMs: 500 },
  },
  {
    id: 'redis',
    category: 'core',
    role: 'required',
    critical: true,
    basis: 'live_probe',
    timeoutMs: 2000,
    onTimeout: 'unavailable',
    purpose: 'Valkey on EC2: BullMQ queues, ZAP locks, scan progress, capacity state.',
    rationale: 'Scans cannot be queued or tracked without it.',
    method: '`PING` on the shared publisher connection (config/redis.js).',
    thresholds: { degradedLatencyMs: 250 },
  },
  {
    id: 'queues',
    category: 'core',
    role: 'required',
    critical: true,
    basis: 'live_probe',
    timeoutMs: 3000,
    onTimeout: 'unavailable',
    purpose: 'BullMQ `scan-queue` and `zap-queue`, processed by workers inside the API task.',
    rationale: 'A stuck queue means scans are accepted but never run.',
    method: 'Job counts per state, and the age of the oldest waiting job. No job payload is returned.',
    // ZAP scans run one at a time and wait for a lock of up to 30 min.
    thresholds: { oldestWaitingSec: { scan: 900, zap: 3600 } },
  },
  {
    id: 'webcheck',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 6000,
    onTimeout: 'unavailable',
    purpose: 'Site analysis service (ECS, Service Connect `webcheck:3000`), always on.',
    rationale: 'Part of every scan; also checked by the public /ready probe.',
    method: 'GET /health on the service.',
    thresholds: { degradedLatencyMs: 3000 },
  },
  {
    id: 'zap',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 6000,
    onTimeout: 'unavailable',
    purpose: 'Vulnerability scanner for normal scans (ECS service `zap-scan-ec2`), scaled to zero when idle.',
    rationale: 'Its absence fails the vulnerability part of every normal scan.',
    method: 'Version call to the ZAP API; if it does not answer, ECS desired/running counts decide idle, starting or unavailable.',
  },
  {
    id: 'zap_auth',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 6000,
    onTimeout: 'unavailable',
    purpose: 'Vulnerability scanner for authenticated scans (ECS service `zap-auth-task-ec2`), scaled to zero when idle.',
    rationale: 'Its absence fails every authenticated scan.',
    method: 'As for ZAP, using the auth instance’s request configuration (Host header).',
  },
  {
    id: 'gemini',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 6000,
    onTimeout: 'unavailable',
    cacheTtlMs: 300_000,
    purpose: 'Vertex AI (workload identity federation) writes the AI report for every scan.',
    rationale: 'When it fails, scans silently get the structured fallback report instead.',
    method: 'countTokens on GEMINI_MODEL_PRO and GEMINI_MODEL_FLASH through the same client and WIF credentials the scans use: proves auth, project, API, IAM permission and regional model availability without generating anything (not billed). Plus AI-report outcomes recorded by this task.',
    thresholds: { minSamples: 3, failureRatio: 0.5 },
  },
  {
    id: 'pagespeed',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 5000,
    onTimeout: 'unavailable',
    cacheTtlMs: 300_000,
    purpose: 'Performance, accessibility and SEO scores in every scan.',
    rationale: 'A revoked key, disabled API or exhausted quota fails this part of every report.',
    method: 'One runPagespeed request with the API key and a deliberately invalid URL: Google validates the key and API access, then rejects the URL, so no Lighthouse audit runs (one query of quota, at most every 5 min). Plus outcomes in customer scans over the last 24 h.',
    thresholds: { windowHours: 24, minSamples: 3, failureRatio: 0.5 },
  },
  {
    id: 'observatory',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'recent_activity',
    timeoutMs: 3000,
    onTimeout: 'unknown',
    purpose: 'HTTP security-header grading in every scan (public API, no key).',
    rationale: 'Its grade is part of every report and the AI summary.',
    method: 'Outcomes in customer scans over the last 24 h. A live call would scan a real site.',
    thresholds: { windowHours: 24, minSamples: 3, failureRatio: 0.5 },
  },
  {
    id: 'urlscan',
    category: 'scanner',
    role: 'dependency',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 5000,
    onTimeout: 'unavailable',
    cacheTtlMs: 300_000,
    purpose: 'Screenshot and page analysis in every scan.',
    rationale: 'A revoked key or exhausted quota fails the screenshot.',
    method: 'GET /user/quotas/ with the API key: authenticates and reads remaining quota without spending any. Plus outcomes over the last 24 h.',
    thresholds: { windowHours: 24, minSamples: 3, failureRatio: 0.5 },
  },
  {
    id: 'stripe',
    category: 'billing',
    role: 'required',
    critical: false,
    basis: 'live_probe',
    timeoutMs: 5000,
    onTimeout: 'unavailable',
    purpose: 'Checkout, subscriptions and cancellations.',
    rationale: 'Without it nobody can buy or cancel, and admin cancel/delete refuse to run.',
    method: 'Retrieve one configured price (read-only; no charge, customer or subscription is touched). Reports whether the key is in live mode.',
  },
  {
    id: 'stripe_webhooks',
    category: 'billing',
    role: 'required',
    critical: false,
    basis: 'app_signal',
    timeoutMs: 3000,
    onTimeout: 'unknown',
    purpose: 'Stripe → Fortexa events that keep plan state in step with billing.',
    rationale: 'Failed webhooks leave plans out of date until the 5-minute reconcile sweep.',
    method: 'Webhook outcomes recorded by this task since it started; events received in the last 7 days (idempotency store).',
  },
  {
    id: 'email',
    category: 'messaging',
    role: 'required',
    critical: false,
    basis: 'aws_api',
    timeoutMs: 4000,
    onTimeout: 'unknown',
    purpose: 'Amazon SES: sign-in OTPs (every admin sign-in), invites, password resets.',
    rationale: 'If sending stops, nobody can complete an OTP sign-in.',
    method: 'SES GetAccountSendingEnabled and GetSendQuota (read-only; nothing is sent).',
    thresholds: { quotaUsedRatio: 0.9 },
  },
  {
    id: 'aws_backend',
    category: 'infrastructure',
    role: 'required',
    critical: false,
    basis: 'aws_api',
    timeoutMs: 5000,
    onTimeout: 'unknown',
    purpose: 'ECS service running the API and the load balancer in front of it.',
    rationale: 'Shows failed deployments, missing tasks and unhealthy targets that a single task cannot see from inside.',
    method: 'ECS DescribeServices (backend service), ELB DescribeTargetHealth, CloudWatch 5xx and request counts for the last 15 min. Resources come from server configuration only.',
    thresholds: { http5xxRatio: 0.05, minRequests: 20 },
  },
  {
    id: 'aws_alarms',
    category: 'infrastructure',
    role: 'required',
    critical: false,
    basis: 'aws_api',
    timeoutMs: 5000,
    onTimeout: 'unknown',
    purpose: 'CloudWatch alarms for Fortexa (Valkey host, backend API once created).',
    rationale: 'One place to see whether any production alarm is firing.',
    method: 'CloudWatch DescribeAlarms for the configured name prefix.',
  },
];

// Considered and deliberately not shown. Kept here so the decision is explicit
// and a test can check none of these ever appears on the page.
const EXCLUDED = [
  {
    id: 'cdn',
    name: 'S3 + CloudFront (frontend)',
    usage: 'production',
    reason: 'An administrator viewing this page has just loaded it through CloudFront, so a server-side probe adds nothing; S3 is reachable only through CloudFront (origin access control).',
  },
  {
    id: 'translate',
    name: 'Google Translate (unofficial client)',
    usage: 'production, optional',
    reason: 'No check exists that does not translate text; a failure only affects the Japanese AI report and is reported to the user per request.',
  },
  {
    id: 'elasticache',
    name: 'ElastiCache',
    usage: 'retired',
    reason: 'Cluster deleted 2026-10-03; production uses Valkey on EC2 (covered by "redis").',
  },
  {
    id: 'gemini_api_key',
    name: 'Gemini via AI Studio API key',
    usage: 'development only',
    reason: 'Production uses Vertex AI through workload identity; the API-key mode is rejected on ECS.',
  },
  {
    id: 'cloudwatch_logs',
    name: 'CloudWatch Logs',
    usage: 'production',
    reason: 'Written by the ECS log driver, not the application; its health is not observable from inside the task. Log-based alarms appear under "aws_alarms".',
  },
];

const byId = new Map(INVENTORY.map((s) => [s.id, s]));

module.exports = {
  INVENTORY,
  EXCLUDED,
  SERVICE_IDS: INVENTORY.map((s) => s.id),
  getService: (id) => byId.get(id) || null,
  STATUSES: ['healthy', 'degraded', 'unavailable', 'starting', 'idle', 'configured', 'unknown'],
};
