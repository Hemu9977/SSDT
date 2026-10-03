#!/bin/bash
# Creates (or, on re-run, updates) the two Secrets Manager secrets the EC2 Valkey needs.
# Never prints secret material.
#
#   fortexa-redis/host  read ONLY by fortexa-redis-instance-role (resource policy below):
#                       server cert/key, CA cert, ACL SHA-256 hashes, ops-admin password
#   fortexa-redis/app   read by the backend task definition (ecsTaskExecutionRole):
#                       REDIS_URL (rediss://fortexa-app:...@redis.fortexa.internal:6379),
#                       REDIS_TLS_CA, REDIS_TLS_SERVERNAME
#
# Inputs come from the offline PKI directory (default ~/.fortexa-redis-pki):
#   ca.crt  server.crt  server.key  passwords.json {"fortexa_app": "...", "ops_admin": "..."}
# ca.key stays there — it is never uploaded.
#
#   AWS_PROFILE=ssdt-profile bash infrastructure/redis-ec2/create-secrets.sh
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER=""
PKI=${PKI:-$HOME/.fortexa-redis-pki}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/fortexa-redis-instance-role"

for f in ca.crt server.crt server.key passwords.json; do
  [ -s "$PKI/$f" ] || { echo "missing $PKI/$f" >&2; exit 1; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Node on Windows cannot open Git Bash paths such as /tmp/... or /c/Users/...
native() { case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) cygpath -m "$1" ;; *) printf '%s' "$1" ;; esac; }
TMPW=$(native "$TMP")
ROLE_ARN="$ROLE_ARN" PKI="$(native "$PKI")" TMP="$TMPW" node -e '
const fs = require("fs"), c = require("crypto");
const P = process.env.PKI, T = process.env.TMP;
const pw = JSON.parse(fs.readFileSync(P + "/passwords.json", "utf8"));
const sha = s => c.createHash("sha256").update(s).digest("hex");
const ca = fs.readFileSync(P + "/ca.crt", "utf8");
if (!/^[A-Za-z0-9]{32,}$/.test(pw.fortexa_app) || !/^[A-Za-z0-9]{32,}$/.test(pw.ops_admin))
  throw new Error("passwords must be >= 32 URL-safe alphanumerics");
fs.writeFileSync(T + "/host.json", JSON.stringify({
  server_crt: fs.readFileSync(P + "/server.crt", "utf8"),
  server_key: fs.readFileSync(P + "/server.key", "utf8"),
  ca_crt: ca,
  app_sha256: sha(pw.fortexa_app),
  app_sha256_next: pw.fortexa_app_next ? sha(pw.fortexa_app_next) : "",
  admin_sha256: sha(pw.ops_admin),
  admin_password: pw.ops_admin
}));
fs.writeFileSync(T + "/app.json", JSON.stringify({
  REDIS_URL: "rediss://fortexa-app:" + pw.fortexa_app + "@redis.fortexa.internal:6379",
  REDIS_TLS_CA: ca,
  REDIS_TLS_SERVERNAME: "redis.fortexa.internal"
}));
fs.writeFileSync(T + "/policy.json", JSON.stringify({
  Version: "2012-10-17",
  Statement: [{ Sid: "FortexaRedisInstanceOnly", Effect: "Allow",
    Principal: { AWS: process.env.ROLE_ARN }, Action: "secretsmanager:GetSecretValue", Resource: "*" }]
}));
'

FILE_PREFIX="file://"

upsert() { # name description file
  if aws secretsmanager describe-secret --secret-id "$1" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --secret-id "$1" --secret-string "${FILE_PREFIX}${TMPW}/$3" --query VersionId --output text >/dev/null
    echo "updated  $1"
  else
    aws secretsmanager create-secret --name "$1" --description "$2" --secret-string "${FILE_PREFIX}${TMPW}/$3" \
      --tags Key=App,Value=fortexa Key=Role,Value=redis --query ARN --output text >/dev/null
    echo "created  $1"
  fi
}

upsert fortexa-redis/host \
  "Fortexa EC2 Valkey host material: TLS cert/key, CA, ACL hashes, ops-admin password. Readable only by fortexa-redis-instance-role." \
  host.json
upsert fortexa-redis/app \
  "Fortexa backend connection to the EC2 Valkey: REDIS_URL, REDIS_TLS_CA, REDIS_TLS_SERVERNAME. Used by the backend task definition." \
  app.json

aws secretsmanager put-resource-policy --secret-id fortexa-redis/host \
  --resource-policy "${FILE_PREFIX}${TMPW}/policy.json" --block-public-policy --query Name --output text >/dev/null
echo "resource policy on fortexa-redis/host -> $ROLE_ARN"

aws secretsmanager describe-secret --secret-id fortexa-redis/host --query ARN --output text
aws secretsmanager describe-secret --secret-id fortexa-redis/app --query ARN --output text
echo "done (no secret values were printed)"
