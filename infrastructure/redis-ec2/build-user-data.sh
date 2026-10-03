#!/bin/bash
# Packs this directory into a self-extracting EC2 user-data script (stdout).
# EC2 user-data is capped at 16 KB, so the files travel as a base64 tar.gz.
#   ./build-user-data.sh > /tmp/fortexa-redis-user-data.sh
set -euo pipefail
cd "$(dirname "$0")"
FILES="bootstrap.sh valkey.conf users.acl.tmpl valkey-override.conf sysctl-valkey.conf disable-thp.service
fortexa-valkey-secrets fortexa-valkey-secrets.service fortexa-valkey-metrics fortexa-valkey-metrics.service
fortexa-valkey-metrics.timer cloudwatch-agent.json"
PAYLOAD=$(tar -czf - $FILES | base64 -w0)
cat <<EOF
#!/bin/bash
set -euo pipefail
mkdir -p /opt/fortexa-redis
echo '$PAYLOAD' | base64 -d | tar -xzf - -C /opt/fortexa-redis
sed -i 's/\r\$//' /opt/fortexa-redis/*
chmod +x /opt/fortexa-redis/bootstrap.sh
SRC=/opt/fortexa-redis REGION=\${REGION:-ap-northeast-1} HOST_SECRET_ID=\${HOST_SECRET_ID:-fortexa-redis/host} MAXMEMORY=\${MAXMEMORY:-1gb} \\
  /opt/fortexa-redis/bootstrap.sh
EOF
