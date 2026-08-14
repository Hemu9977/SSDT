/**
 * ZAP Container Manager
 * Manages ZAP scanner containers — spins up a fresh ECS Fargate task per scan
 * and tears it down when the scan completes.
 *
 * In local/dev mode (ECS_CLUSTER_NAME not set), falls back to the pre-configured
 * ZAP URLs from environment variables so no code changes are needed for local dev.
 */

const axios = require('axios');

// Gated on an explicit opt-in rather than on ECS_CLUSTER_NAME. That variable is also
// read by restartZapContainer() in zapService.js, and keying off it there would silently
// activate the per-scan container path below — which still targets Fargate, the container
// name 'zap' and the family 'ssdt-zap-task', none of which match the live EC2 setup.
// Leave this false until that drift is fixed and per-scan routing is wired up.
const IS_AWS = process.env.ZAP_EPHEMERAL_CONTAINERS === 'true';

// Eagerly load SDK only when running in AWS — avoids ~10MB parse cost in local dev
// and eliminates repeated require() calls inside hot-path functions.
let ECSClient, RunTaskCommand, StopTaskCommand, DescribeTasksCommand;
if (IS_AWS) {
  ({ ECSClient, RunTaskCommand, StopTaskCommand, DescribeTasksCommand } =
    require('@aws-sdk/client-ecs'));
}

const CLUSTER_NAME   = process.env.ECS_CLUSTER_NAME   || 'ssdt-cluster';
const ZAP_TASK_DEF   = process.env.ECS_ZAP_TASK_DEF   || 'ssdt-zap-task';
const SUBNET_IDS     = (process.env.ECS_SUBNET_IDS    || '').split(',').filter(Boolean);
const SECURITY_GROUP = process.env.ECS_SECURITY_GROUP  || '';
const AWS_REGION     = process.env.AWS_REGION          || 'ap-south-1';

// Shared ECS client (one connection pool per process).
const ecsClient = IS_AWS ? new ECSClient({ region: AWS_REGION }) : null;

// scanId → { taskArn, zapUrl, startedAt }
const activeContainers = new Map();

// Remove entries older than 8 hours — guards against orphaned entries when
// releaseContainer is never called due to an unhandled crash or SIGKILL.
const CONTAINER_TTL_MS = 8 * 60 * 60 * 1000;
if (IS_AWS) {
  setInterval(() => {
    const cutoff = Date.now() - CONTAINER_TTL_MS;
    for (const [scanId, info] of activeContainers) {
      if (info.startedAt.getTime() < cutoff) {
        console.warn(`[ContainerMgr] Pruning orphaned container entry: ${scanId}`);
        activeContainers.delete(scanId);
      }
    }
  }, 60 * 1000).unref(); // unref so this timer doesn't keep the process alive
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Request a ZAP container for a scan.
 * - AWS mode: spin up a fresh Fargate task, wait until healthy, return private IP URL.
 * - Local mode: immediately return the locally configured ZAP URL.
 *
 * @param {string} scanId  - Unique scan identifier (used as ECS task tag)
 * @param {'public'|'auth'} type - Scan type (determines which URL to return in local mode)
 * @returns {Promise<{ zapUrl: string, taskArn: string|null }>}
 */
async function requestContainer(scanId, type = 'public') {
  if (!IS_AWS) {
    const zapUrl = type === 'auth'
      ? (process.env.ZAP_AUTH_API_URL || 'http://127.0.0.1:8081')
      : (process.env.ZAP_API_URL      || 'http://127.0.0.1:8080');
    console.log(`[ContainerMgr] Local mode — using ${zapUrl} for scan: ${scanId}`);
    return { zapUrl, taskArn: null };
  }

  console.log(`[ContainerMgr] AWS mode — spinning up ZAP container for scan: ${scanId}`);

  const command = new RunTaskCommand({
    cluster: CLUSTER_NAME,
    taskDefinition: ZAP_TASK_DEF,
    launchType: 'FARGATE',
    count: 1,
    networkConfiguration: {
      awsvpcConfiguration: {
        subnets: SUBNET_IDS,
        securityGroups: [SECURITY_GROUP],
        assignPublicIp: 'DISABLED'
      }
    },
    overrides: {
      containerOverrides: [{ name: 'zap', environment: [{ name: 'SCAN_ID', value: scanId }] }]
    },
    tags: [{ key: 'scanId', value: scanId }, { key: 'project', value: 'ssdt' }]
  });

  const response = await ecsClient.send(command);

  if (!response.tasks || response.tasks.length === 0) {
    throw new Error('ECS RunTask returned no tasks');
  }

  const taskArn = response.tasks[0].taskArn;
  console.log(`[ContainerMgr] Task launched: ${taskArn}`);

  const zapUrl = await waitForTaskReady(taskArn);

  activeContainers.set(scanId, { taskArn, zapUrl, startedAt: new Date() });
  console.log(`[ContainerMgr] ZAP ready at ${zapUrl} for scan: ${scanId}`);
  return { zapUrl, taskArn };
}

/**
 * Stop and clean up a ZAP container.
 * No-op in local mode. Always removes the Map entry even if StopTask fails
 * so the orphan-pruning interval is a last resort, not the primary mechanism.
 *
 * @param {string} scanId
 */
async function releaseContainer(scanId) {
  if (!IS_AWS) return;

  const container = activeContainers.get(scanId);
  if (!container) return;

  console.log(`[ContainerMgr] Releasing container for scan: ${scanId}`);

  try {
    await ecsClient.send(new StopTaskCommand({
      cluster: CLUSTER_NAME,
      task: container.taskArn,
      reason: `Scan ${scanId} completed`
    }));
  } catch (err) {
    console.error(`[ContainerMgr] Failed to stop task for scan ${scanId}: ${err.message}`);
  } finally {
    // Always remove from map regardless of StopTask outcome.
    activeContainers.delete(scanId);
  }
}

/**
 * Return a snapshot of all currently tracked containers (for admin/monitoring).
 */
function getActiveContainers() {
  return Array.from(activeContainers.entries()).map(([scanId, info]) => ({
    scanId,
    zapUrl: info.zapUrl,
    taskArn: info.taskArn,
    startedAt: info.startedAt,
    runningMinutes: Math.round((Date.now() - info.startedAt) / 60000)
  }));
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

async function waitForTaskReady(taskArn, maxWaitMs = 300000) {
  const startTime = Date.now();

  while (Date.now() - startTime < maxWaitMs) {
    const desc = await ecsClient.send(new DescribeTasksCommand({
      cluster: CLUSTER_NAME,
      tasks: [taskArn]
    }));

    const task = desc.tasks && desc.tasks[0];
    if (!task) throw new Error('Task not found in ECS');

    if (task.lastStatus === 'RUNNING') {
      const eni = (task.attachments || []).find(a => a.type === 'ElasticNetworkInterface');
      const privateIp = (eni?.details || []).find(d => d.name === 'privateIPv4Address')?.value;

      if (privateIp) {
        const zapUrl = `http://${privateIp}:8080`;
        await waitForZapApi(zapUrl);
        return zapUrl;
      }
    }

    if (task.lastStatus === 'STOPPED') {
      throw new Error(`ZAP container stopped unexpectedly: ${task.stoppedReason || 'unknown reason'}`);
    }

    await sleep(5000);
  }

  throw new Error('Timed out waiting for ZAP Fargate task to become ready (5 min limit)');
}

async function waitForZapApi(zapUrl, maxWaitMs = 90000) {
  const startTime = Date.now();

  while (Date.now() - startTime < maxWaitMs) {
    try {
      await axios.get(`${zapUrl}/JSON/core/view/version/`, { timeout: 5000 });
      console.log(`[ContainerMgr] ZAP API healthy at ${zapUrl}`);
      return;
    } catch {
      await sleep(3000);
    }
  }

  throw new Error(`ZAP API at ${zapUrl} did not respond within 90 seconds`);
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

module.exports = { requestContainer, releaseContainer, getActiveContainers };
