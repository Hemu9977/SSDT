#!/bin/bash
# Writes a register-ready backend task definition that points REDIS_URL at the EC2
# Valkey. READ-ONLY against AWS: it describes the live service's current revision and
# the fortexa-redis/app secret, and writes JSON to a local file. It registers nothing
# and deploys nothing.
#
#   bash infrastructure/redis-ec2/render-backend-taskdef.sh <NEW_IMAGE_TAG> > /tmp/td.json
#   aws ecs register-task-definition --cli-input-json file:///tmp/td.json
#   aws ecs update-service --cluster fortexa-cluster --service fortexa-ec2-backend \
#       --task-definition fortexa-backend:<new revision>
#
# Rollback = update-service back to the revision this script read (printed on stderr).
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER=""
CLUSTER=${CLUSTER:-fortexa-cluster}
SERVICE=${SERVICE:-fortexa-ec2-backend}
IMAGE_TAG=${1:-}

# The image MUST contain backend/config/redis.js with REDIS_TLS_CA support (tlsOptions).
# An older image cannot verify the private-CA certificate, so every Redis connection —
# and therefore every scan — would fail. Hence: an explicit new tag is required.
if [ -z "$IMAGE_TAG" ]; then
  echo "usage: $0 <IMAGE_TAG>   (a backend image built from code that includes REDIS_TLS_CA support)" >&2
  exit 2
fi

LIVE_TD=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --query 'services[0].taskDefinition' --output text)
LIVE_TAG=$(aws ecs describe-task-definition --task-definition "$LIVE_TD" --query 'taskDefinition.containerDefinitions[0].image' --output text | sed 's/.*://')
if [ "$IMAGE_TAG" = "$LIVE_TAG" ] && [ "${FORCE:-}" != "1" ]; then
  echo "refusing: $IMAGE_TAG is the image already live, which predates REDIS_TLS_CA support." >&2
  echo "Build and push a new image from the current code first (or FORCE=1 if you are sure it has the change)." >&2
  exit 2
fi
APP_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id fortexa-redis/app --query ARN --output text)
echo "live task definition (rollback target): $LIVE_TD" >&2
echo "redis app secret: $APP_SECRET_ARN" >&2

aws ecs describe-task-definition --task-definition "$LIVE_TD" --query taskDefinition --output json |
APP_SECRET_ARN="$APP_SECRET_ARN" IMAGE_TAG="$IMAGE_TAG" node -e '
let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
  const td = JSON.parse(s);
  // Keep only the fields register-task-definition accepts.
  const keep = ["family","taskRoleArn","executionRoleArn","networkMode","containerDefinitions","volumes",
    "placementConstraints","requiresCompatibilities","cpu","memory","pidMode","ipcMode","proxyConfiguration",
    "inferenceAccelerators","ephemeralStorage","runtimePlatform"];
  const out = Object.fromEntries(Object.entries(td).filter(([k, v]) => keep.includes(k) && v !== undefined && v !== null));
  const arn = process.env.APP_SECRET_ARN;
  const c = out.containerDefinitions.find(x => x.name === "backend") || out.containerDefinitions[0];
  const drop = new Set(["REDIS_URL", "REDIS_TLS_CA", "REDIS_TLS_SERVERNAME"]);
  c.secrets = (c.secrets || []).filter(x => !drop.has(x.name));
  c.secrets.push(
    { name: "REDIS_URL",            valueFrom: `${arn}:REDIS_URL::` },
    { name: "REDIS_TLS_CA",         valueFrom: `${arn}:REDIS_TLS_CA::` },
    { name: "REDIS_TLS_SERVERNAME", valueFrom: `${arn}:REDIS_TLS_SERVERNAME::` });
  c.environment = (c.environment || []).filter(x => !drop.has(x.name));
  if (process.env.IMAGE_TAG) c.image = c.image.replace(/:[^:/]+$/, ":" + process.env.IMAGE_TAG);
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  console.error(`image: ${c.image}`);
  console.error("REDIS_* now come from fortexa-redis/app; every other variable and secret is unchanged.");
});'
