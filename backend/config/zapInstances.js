'use strict';

/**
 * Per-ZAP-instance configuration, shared by zapRecycler and zapCapacityManager.
 *
 * This block used to live inside zapRecycler.js. It was lifted out when the capacity
 * manager was added: the recycler needs `ensureZapCapacity` and the capacity manager
 * needs the service names, base URLs and probe headers, so leaving it in place would
 * have created a circular require between the two.
 *
 * Every field is a getter, read lazily, so a task-definition env change takes effect
 * without a code change and tests can override process.env.
 *
 * Redis key naming: `zap:<concern>:<instance>`. The three capacity keys are new; the
 * two lock keys are unchanged and must stay byte-identical, because a running backend
 * may still hold a lock under the old name during a rolling deploy.
 */

const INSTANCES = {
  normal: {
    label: 'normal',

    // Held for the duration of a scan. Unchanged name — see note above.
    lockKey: 'zap:lock:normal',
    // Held only for the duration of a recycle.
    recycleLockKey: 'zap:recycle:normal',

    // Held only while a scale-out is in flight. This is what stops N concurrent scan
    // starts from issuing N UpdateService calls and N ASG scale-outs.
    capacityLockKey: 'zap:capacity:lock:normal',
    // Observability only — correctness never depends on reading this.
    capacityStateKey: 'zap:capacity:state:normal',
    // Timestamp of the most recent scan acceptance; read by the idle scale-in check.
    demandKey: 'zap:capacity:demand:normal',
    // Task ARN of a task that was started by a scale-from-zero and has already been
    // proven to answer the ZAP API. ARN-scoped on purpose: a stale marker can never
    // cause a *different* task's recycle to be skipped.
    coldStartKey: 'zap:capacity:coldstart:normal',

    service: () => process.env.ECS_ZAP_SERVICE || 'zap-scan-ec2',
    baseUrl: () => process.env.ZAP_API_URL || 'http://127.0.0.1:8080',
    // Mirrors createZapClient in zapService.js — no special headers.
    probeConfig: () => ({})
  },

  auth: {
    label: 'auth',

    lockKey: 'zap:lock:auth',
    recycleLockKey: 'zap:recycle:auth',

    capacityLockKey: 'zap:capacity:lock:auth',
    capacityStateKey: 'zap:capacity:state:auth',
    demandKey: 'zap:capacity:demand:auth',
    coldStartKey: 'zap:capacity:coldstart:auth',

    service: () => process.env.ECS_ZAP_AUTH_SERVICE || 'zap-auth-task-ec2',
    baseUrl: () => process.env.ZAP_AUTH_API_URL || 'http://127.0.0.1:8081',
    // Mirrors createZapAuthClient in zapAuthService.js: ZAP's API validation is
    // Host-header-sensitive and it always listens on 8080 internally.
    probeConfig: () => ({
      headers: {
        Host: 'localhost:8080',
        ...(process.env.ZAP_AUTH_API_KEY ? { 'X-Zap-Api-Key': process.env.ZAP_AUTH_API_KEY } : {})
      },
      ...(process.env.ZAP_AUTH_API_KEY ? { params: { apikey: process.env.ZAP_AUTH_API_KEY } } : {})
    })
  }
};

const INSTANCE_KEYS = Object.keys(INSTANCES);

function getInstance(key) {
  const inst = INSTANCES[key];
  if (!inst) throw new Error(`Unknown ZAP instance key: ${key}`);
  return inst;
}

module.exports = { INSTANCES, INSTANCE_KEYS, getInstance };
