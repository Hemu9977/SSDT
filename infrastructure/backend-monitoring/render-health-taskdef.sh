#!/bin/bash
# Writes a register-ready backend task definition with the admin System Health
# settings added. READ-ONLY against AWS: it describes the live service, its task
# definition, the load balancer and target group, and writes JSON to stdout. It
# registers nothing and deploys nothing.
#
#   bash infrastructure/backend-monitoring/render-health-taskdef.sh <NEW_IMAGE_TAG> [GIT_SHA] > td.json
#   aws ecs register-task-definition --cli-input-json file://td.json
#   aws ecs update-service --cluster fortexa-cluster --service fortexa-ec2-backend \
#       --task-definition fortexa-backend:<new revision>
#
# Rollback = update-service back to the revision this script read (printed on stderr).
# The IAM policy in system-health-iam-policy.json must be applied first, or the two
# AWS cards read "Unknown — permission denied" (nothing else is affected).
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1
CLUSTER=${CLUSTER:-fortexa-cluster}
SERVICE=${SERVICE:-fortexa-ec2-backend}
TG_NAME=${TG_NAME:-fortexa-tg}
LB_NAME=${LB_NAME:-fortexa-alb}
IMAGE_TAG=${1:-}
GIT_SHA=${2:-}

# The image must contain backend/services/systemHealth.js and the CloudWatch/ELB SDK
# clients. The live image predates them, so an explicit new tag is required.
if [ -z "$IMAGE_TAG" ]; then
  echo "usage: $0 <IMAGE_TAG> [GIT_SHA]   (an image built from code with services/systemHealth.js)" >&2
  exit 2
fi

LIVE_TD=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --query 'services[0].taskDefinition' --output text)
LIVE_TAG=$(aws ecs describe-task-definition --task-definition "$LIVE_TD" --query 'taskDefinition.containerDefinitions[0].image' --output text | sed 's/.*://')
if [ "$IMAGE_TAG" = "$LIVE_TAG" ] && [ "${FORCE:-}" != "1" ]; then
  echo "refusing: $IMAGE_TAG is the image already live, which predates the System Health checks." >&2
  exit 2
fi
TG_ARN=$(aws elbv2 describe-target-groups --names "$TG_NAME" --query 'TargetGroups[0].TargetGroupArn' --output text)
LB_ARN=$(aws elbv2 describe-load-balancers --names "$LB_NAME" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
echo "live task definition (rollback target): $LIVE_TD" >&2
echo "target group: $TG_ARN" >&2
echo "load balancer: $LB_ARN" >&2

aws ecs describe-task-definition --task-definition "$LIVE_TD" --query taskDefinition --output json |
SERVICE="$SERVICE" TG_ARN="$TG_ARN" LB_ARN="$LB_ARN" IMAGE_TAG="$IMAGE_TAG" GIT_SHA="$GIT_SHA" node -e '
let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
  const td = JSON.parse(s);
  const keep = ["family","taskRoleArn","executionRoleArn","networkMode","containerDefinitions","volumes",
    "placementConstraints","requiresCompatibilities","cpu","memory","pidMode","ipcMode","proxyConfiguration",
    "inferenceAccelerators","ephemeralStorage","runtimePlatform"];
  const out = Object.fromEntries(Object.entries(td).filter(([k, v]) => keep.includes(k) && v !== undefined && v !== null));
  const c = out.containerDefinitions.find(x => x.name === "backend") || out.containerDefinitions[0];
  const add = {
    HEALTH_ECS_SERVICE: process.env.SERVICE,
    HEALTH_ALB_TARGET_GROUP_ARN: process.env.TG_ARN,
    HEALTH_ALB_LOAD_BALANCER_ARN: process.env.LB_ARN,
    HEALTH_ALARM_PREFIX: "fortexa-",
    ...(process.env.GIT_SHA ? { GIT_SHA: process.env.GIT_SHA } : {}),
  };
  c.environment = (c.environment || []).filter(x => !(x.name in add));
  for (const [name, value] of Object.entries(add)) c.environment.push({ name, value });
  for (const need of ["ECS_CLUSTER_NAME", "USE_AWS_SES", "AWS_REGION"]) {
    if (!c.environment.some(x => x.name === need)) console.error(`WARNING: ${need} is not set; a System Health card will read "not configured".`);
  }
  c.image = c.image.replace(/(@sha256:[0-9a-f]+|:[^:/]+)$/, ":" + process.env.IMAGE_TAG);
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  console.error(`image: ${c.image}`);
  console.error("Added: " + Object.keys(add).join(", ") + ". Every other variable and secret is unchanged.");
});'
