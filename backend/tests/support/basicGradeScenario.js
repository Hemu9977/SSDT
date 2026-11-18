'use strict';

/**
 * Runs one real-network scenario of the header grade's HTTP Basic credential guard
 * and prints a JSON summary on the last stdout line. Spawned by
 * tests/basicAuthSiteChecks.test.js in its own process, so the grading engine's
 * sockets, the patched dns.lookup and the servers never share the test runner's
 * stdout channel (under full-suite load that corrupted the runner's frames).
 *
 *   node tests/support/basicGradeScenario.js <hop|manual>
 */

const fs = require('node:fs');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');

const TLS = {
  key: fs.readFileSync(path.join(__dirname, '../fixtures/tls/test-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../fixtures/tls/test-cert.pem')),
};
const USER = 'scan-user';
const PASS = 'S3cret-basic-PW';
const AUTH = `Basic ${Buffer.from(`${USER}:${PASS}`).toString('base64')}`;

// The engine refuses hostnames without a public TLD, so the names live under
// basic-test.jp and resolve to 127.0.0.1 in this process only.
const FAKE = /(^|\.)basic-test\.jp$/i;
const realLookup = dns.lookup;
dns.lookup = function lookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  if (typeof options === 'number') options = { family: options };
  if (!FAKE.test(hostname)) return realLookup.call(dns, hostname, options, cb);
  if (options && options.all) return process.nextTick(cb, null, [{ address: '127.0.0.1', family: 4 }]);
  return process.nextTick(cb, null, '127.0.0.1', 4);
};

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function recorder(kind, handler) {
  const seen = [];
  const fn = (req, res) => {
    seen.push({ host: String(req.headers.host || ''), path: req.url, auth: req.headers.authorization || null });
    handler(req, res);
  };
  const server = kind === 'https' ? https.createServer(TLS, fn) : http.createServer(fn);
  return { server, seen };
}

/** For each recorded request: did it carry THIS credential, another value, or nothing. */
const summarize = (seen) => seen.map(r => ({ host: r.host.split(':')[0], path: r.path, auth: r.auth === AUTH ? 'credential' : r.auth ? 'other' : null }));

async function hop() {
  const plain = recorder('http', (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html></html>'); });
  const plainPort = await listen(plain.server);
  // robots.txt redirects (an automatic hop) to a SUBDOMAIN on the SAME port — the one
  // case follow-redirects keeps Authorization for. The same server answers it.
  const target = recorder('https', (req, res) => {
    if (String(req.headers.host || '').startsWith('sub.')) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: *'); }
    if (req.url.startsWith('/robots.txt')) {
      res.writeHead(302, { location: `https://sub.target.basic-test.jp:${req.socket.localPort}/robots.txt` });
      return res.end();
    }
    if (req.headers.authorization !== AUTH) { res.writeHead(401, { 'www-authenticate': 'Basic realm="t"' }); return res.end(); }
    res.writeHead(200, {
      'content-type': 'text/html',
      'strict-transport-security': 'max-age=63072000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
    });
    res.end('<!doctype html><html><head><title>signed in</title></head><body>ok</body></html>');
  });
  const targetPort = await listen(target.server);
  const headerGrade = require('../../services/inHouse/headerGrade');
  const cred = { origin: `https://target.basic-test.jp:${targetPort}`, username: USER, password: PASS };
  // A concurrent unauthenticated grading of the same host must not inherit the credential.
  const [graded, publicGrade] = await Promise.all([
    headerGrade.gradeHostWithBasicAuth('target.basic-test.jp', cred, { httpPort: plainPort }),
    headerGrade._gradeUncached('target.basic-test.jp', { httpsPort: targetPort, httpPort: plainPort }),
  ]);
  return {
    target: summarize(target.seen), plain: summarize(plain.seen),
    graded: { status: graded.observatory.status_code, grade: graded.observatory.grade, tlsGrade: graded.tls.tlsInfo.grade },
    publicStatus: publicGrade.status_code,
  };
}

async function manual() {
  const other = recorder('https', (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html></html>'); });
  const otherPort = await listen(other.server);
  const target = recorder('https', (req, res) => {
    if (req.headers.authorization !== AUTH) { res.writeHead(401, { 'www-authenticate': 'Basic realm="t"' }); return res.end(); }
    res.writeHead(302, { location: `https://other.basic-test.jp:${otherPort}/landing` });
    res.end();
  });
  const targetPort = await listen(target.server);
  const plain = recorder('http', (req, res) => { res.writeHead(404); res.end(); });
  const plainPort = await listen(plain.server);
  const headerGrade = require('../../services/inHouse/headerGrade');
  await headerGrade.gradeHostWithBasicAuth('target.basic-test.jp',
    { origin: `https://target.basic-test.jp:${targetPort}`, username: USER, password: PASS }, { httpPort: plainPort });
  return { target: summarize(target.seen), other: summarize(other.seen), plain: summarize(plain.seen) };
}

const scenarios = { hop, manual };
const name = process.argv[2];
scenarios[name]()
  .then(out => { process.stdout.write(`\nRESULT ${JSON.stringify(out)}\n`); process.exit(0); })
  .catch(err => { process.stdout.write(`\nRESULT ${JSON.stringify({ error: err.message })}\n`); process.exit(1); });
