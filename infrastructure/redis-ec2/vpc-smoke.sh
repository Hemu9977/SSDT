#!/bin/bash
# Runs the Redis verification scripts from INSIDE the Fortexa VPC, exactly the way the
# backend connects: a one-off Fargate task in the backend's private subnets and security
# group, credentials from fortexa-redis/app, code from this working tree
# (backend/config/redis.js + backend/scripts/redis*.js) on top of the deployed backend
# image's node_modules. It does not touch the backend service.
#
#   bash infrastructure/redis-ec2/vpc-smoke.sh full        # TLS/ACL/locks/pubsub/BullMQ suite
#   bash infrastructure/redis-ec2/vpc-smoke.sh security    # every bad connection is refused
#   bash infrastructure/redis-ec2/vpc-smoke.sh write       # leave persistence probes
#   bash infrastructure/redis-ec2/vpc-smoke.sh verify      # check probes survived a restart
#   bash infrastructure/redis-ec2/vpc-smoke.sh netblocked  # from a NON-backend SG: port must be unreachable
set -euo pipefail
cd "$(dirname "$0")/../.."
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1 PYTHONUTF8=1

MODE=${1:-full}
CLUSTER=${CLUSTER:-fortexa-cluster}
SUBNETS=${SUBNETS:-subnet-014a7ae2b498c12d3,subnet-053597cd5e8375650}
BACKEND_SG=${BACKEND_SG:-sg-0a203b60a3700290e}
OTHER_SG=${OTHER_SG:-sg-0b8e30b33c512c4b4}   # VPC default SG: NOT allowed by fortexa-redis-ec2-sg
SG=$BACKEND_SG; [ "$MODE" = "netblocked" ] && SG=$OTHER_SG
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
APP_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id fortexa-redis/app --query ARN --output text)
IMAGE=${IMAGE:-$(aws ecs describe-task-definition --task-definition "$(aws ecs describe-services --cluster "$CLUSTER" \
  --services fortexa-ec2-backend --query 'services[0].taskDefinition' --output text)" \
  --query 'taskDefinition.containerDefinitions[0].image' --output text)}

PAYLOAD=$(node -e '
const fs = require("fs"), z = require("zlib");
const files = {};
for (const p of ["config/redis.js", "scripts/redisMigrationSmoke.js", "scripts/redisSecurityProbe.js"])
  files[p] = fs.readFileSync("backend/" + p, "utf8");
process.stdout.write(z.gzipSync(JSON.stringify(files)).toString("base64"));')

BOOT='const z=require("zlib"),fs=require("fs"),path=require("path"),cp=require("child_process"),net=require("net");
const mode=process.env.SMOKE_MODE;
if(mode==="netblocked"){const u=new URL(process.env.REDIS_URL);const s=net.connect({host:u.hostname,port:+u.port||6379});
 const t=setTimeout(()=>{console.log("PASS  port unreachable from this security group (timeout)");process.exit(0)},8000);
 s.on("connect",()=>{console.log("FAIL  TCP connect SUCCEEDED from a non-backend security group");process.exit(1)});
 s.on("error",e=>{clearTimeout(t);console.log("PASS  port unreachable from this security group: "+e.code);process.exit(0)});}
else{const files=JSON.parse(z.gunzipSync(Buffer.from(process.env.SMOKE_PAYLOAD,"base64")));
 for(const[p,c] of Object.entries(files)){const f="/tmp/smoke/"+p;fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,c);}
 const args=mode==="security"?["/tmp/smoke/scripts/redisSecurityProbe.js"]:["/tmp/smoke/scripts/redisMigrationSmoke.js","--phase="+mode];
 const r=cp.spawnSync("node",args,{stdio:"inherit",env:{...process.env,NODE_PATH:"/app/node_modules"}});process.exit(r.status===null?1:r.status);}'

TD=$(mktemp)
trap 'rm -f "$TD"' EXIT
APP_SECRET_ARN="$APP_SECRET_ARN" IMAGE="$IMAGE" PAYLOAD="$PAYLOAD" BOOT="$BOOT" ACCOUNT="$ACCOUNT" REGION="$AWS_REGION" node -e '
const e = process.env, arn = e.APP_SECRET_ARN;
process.stdout.write(JSON.stringify({
  family: "fortexa-redis-smoke",
  requiresCompatibilities: ["FARGATE"], networkMode: "awsvpc", cpu: "256", memory: "512",
  executionRoleArn: `arn:aws:iam::${e.ACCOUNT}:role/ecsTaskExecutionRole`,
  containerDefinitions: [{
    name: "smoke", image: e.IMAGE, essential: true, user: "node",
    entryPoint: ["node"], command: ["-e", e.BOOT],
    environment: [{ name: "SMOKE_PAYLOAD", value: e.PAYLOAD }, { name: "SMOKE_MODE", value: "full" }],
    secrets: ["REDIS_URL", "REDIS_TLS_CA", "REDIS_TLS_SERVERNAME"].map(n => ({ name: n, valueFrom: `${arn}:${n}::` })),
    logConfiguration: { logDriver: "awslogs", options: {
      "awslogs-group": "/ecs/fortexa-redis-smoke", "awslogs-region": e.REGION,
      "awslogs-stream-prefix": "smoke", "awslogs-create-group": "true" } }
  }]
}));' > "$TD"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) TDW=$(cygpath -m "$TD") ;; *) TDW="$TD" ;; esac
TD_ARN=$(aws ecs register-task-definition --cli-input-json "file://$TDW" --query taskDefinition.taskDefinitionArn --output text)

TASK=$(aws ecs run-task --cluster "$CLUSTER" --launch-type FARGATE --task-definition "$TD_ARN" \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --overrides "{\"containerOverrides\":[{\"name\":\"smoke\",\"environment\":[{\"name\":\"SMOKE_MODE\",\"value\":\"$MODE\"}]}]}" \
  --started-by "redis-vpc-smoke-$MODE" --query 'tasks[0].taskArn' --output text)
echo "mode=$MODE sg=$SG task=${TASK##*/} image=${IMAGE##*/}" >&2
aws ecs wait tasks-stopped --cluster "$CLUSTER" --tasks "$TASK"
EXIT=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" --query 'tasks[0].containers[0].exitCode' --output text)
REASON=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" --query 'tasks[0].stoppedReason' --output text)
aws logs get-log-events --log-group-name /ecs/fortexa-redis-smoke --log-stream-name "smoke/smoke/${TASK##*/}" \
  --start-from-head --query 'events[].message' --output text 2>/dev/null | tr '\t' '\n' | grep -v -E '^\[(Redis|Cleanup)\]' || true
echo "--- exit=$EXIT ($REASON)" >&2
[ "$EXIT" = "0" ]
