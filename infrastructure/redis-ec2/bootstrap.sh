#!/bin/bash
# First-boot provisioning for the Fortexa Valkey EC2 instance (Amazon Linux 2023).
# Invoked by the generated user-data with the files of this directory extracted to
# $SRC. Idempotent: re-running it converges to the same state.
set -euo pipefail
SRC=${SRC:-/opt/fortexa-redis}
REGION=${REGION:-ap-northeast-1}
HOST_SECRET_ID=${HOST_SECRET_ID:-fortexa-redis/host}
MAXMEMORY=${MAXMEMORY:-1gb}
LOG=/var/log/fortexa-redis-bootstrap.log
exec >>"$LOG" 2>&1
echo "== fortexa-redis bootstrap $(date -Is)"

imds() {
  local t
  t=$(curl -sf -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
  curl -sf -H "X-aws-ec2-metadata-token: $t" "http://169.254.169.254/latest/meta-data/$1"
}
INSTANCE_ID=$(imds instance-id)
BIND_IP=$(imds local-ipv4)
echo "instance=$INSTANCE_ID ip=$BIND_IP maxmemory=$MAXMEMORY"

mkdir -p /etc/fortexa /var/lib/fortexa
echo "$INSTANCE_ID" > /var/lib/fortexa/instance-id
cat > /etc/fortexa/redis.env <<EOF
REGION=$REGION
HOST_SECRET_ID=$HOST_SECRET_ID
EOF
chmod 0644 /etc/fortexa/redis.env

# Packages (retry: the NAT path can lag right after launch)
for i in $(seq 1 10); do
  dnf -y install valkey amazon-cloudwatch-agent && break
  echo "dnf attempt $i failed; retrying"; sleep 15
done
rpm -q valkey amazon-cloudwatch-agent
valkey-server --version

# Kernel settings
install -m 0644 "$SRC/sysctl-valkey.conf" /etc/sysctl.d/90-valkey.conf
sysctl --system >/dev/null
install -m 0644 "$SRC/disable-thp.service" /etc/systemd/system/disable-thp.service

# Valkey config + ACL template
sed -e "s/__BIND_IP__/$BIND_IP/" -e "s/__MAXMEMORY__/$MAXMEMORY/" "$SRC/valkey.conf" > /etc/valkey/valkey.conf
chown valkey:root /etc/valkey/valkey.conf && chmod 0640 /etc/valkey/valkey.conf
install -m 0640 -o root -g valkey "$SRC/users.acl.tmpl" /etc/valkey/users.acl.tmpl

# Scripts and units
install -m 0750 -o root -g root "$SRC/fortexa-valkey-secrets" /usr/local/sbin/fortexa-valkey-secrets
install -m 0750 -o root -g root "$SRC/fortexa-valkey-metrics" /usr/local/sbin/fortexa-valkey-metrics
install -m 0644 "$SRC/fortexa-valkey-secrets.service" /etc/systemd/system/
install -m 0644 "$SRC/fortexa-valkey-metrics.service" /etc/systemd/system/
install -m 0644 "$SRC/fortexa-valkey-metrics.timer" /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/valkey.service.d
install -m 0644 "$SRC/valkey-override.conf" /etc/systemd/system/valkey.service.d/override.conf

systemctl daemon-reload
systemctl enable --now disable-thp.service
systemctl enable fortexa-valkey-secrets.service
systemctl start fortexa-valkey-secrets.service
systemctl enable --now valkey.service
systemctl enable --now fortexa-valkey-metrics.timer

# CloudWatch agent (metrics + logs)
install -m 0644 "$SRC/cloudwatch-agent.json" /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

# Self-check (as the ops user, over TLS, exactly like a client would)
export VALKEYCLI_AUTH="$(cat /etc/valkey/ops-admin.pass)"
for i in $(seq 1 30); do
  if [ "$(valkey-cli --no-auth-warning --tls --cacert /etc/valkey/tls/ca.crt --sni redis.fortexa.internal \
        -h 127.0.0.1 -p 6379 --user ops-admin PING 2>/dev/null)" = "PONG" ]; then
    echo "SELF-CHECK OK"; break
  fi
  sleep 2
done
touch /var/lib/fortexa/bootstrap-complete
echo "== bootstrap done $(date -Is)"
