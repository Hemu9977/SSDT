#!/bin/bash
# Limit retention of the backend log groups (audit finding L7).
# NOT RUN AUTOMATICALLY — this changes AWS and deletes log events older than the
# retention period once applied. Needs team approval (and a decision on how long
# logs must be kept for incident investigation and legal holds).
#
#   RETENTION_DAYS=365 bash infrastructure/backend-monitoring/set-log-retention.sh
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1

DAYS=${RETENTION_DAYS:-365}
for GROUP in /ecs/fortexa-backend /ecs/fortexa-backend-service-0qhpn4vc; do
  aws logs put-retention-policy --log-group-name "$GROUP" --retention-in-days "$DAYS"
  echo "ok  $GROUP -> $DAYS days"
done
aws logs describe-log-groups --log-group-name-prefix /ecs/fortexa-backend \
  --query 'logGroups[].[logGroupName,retentionInDays]' --output text
