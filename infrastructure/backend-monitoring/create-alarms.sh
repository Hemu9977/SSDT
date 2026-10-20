#!/bin/bash
# CloudWatch alarms for the Fortexa backend API (audit finding M8).
# NOT RUN AUTOMATICALLY — this changes AWS and needs team approval.
# Idempotent (put-metric-alarm / put-metric-filter upsert).
#
#   ALERT_TOPIC_ARN=arn:aws:sns:ap-northeast-1:<acct>:fortexa-backend-alerts \
#     bash infrastructure/backend-monitoring/create-alarms.sh
#
# Until 2026-10-19 the region had 17 alarms and none for the API: an outage, a DB
# disconnect or a crash loop was found by customers. Dimensions below are the
# production ALB and target group verified that day (docs/ADMIN_DASHBOARD_AUDIT.md §3.3).
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1

TOPIC=${ALERT_TOPIC_ARN:?set ALERT_TOPIC_ARN to an SNS topic that pages on-call}
LB=${LB_DIMENSION:-app/fortexa-alb/96dcec7a7809f822}
TG=${TG_DIMENSION:-targetgroup/fortexa-tg/6a576c2b619be6c3}
LOG_GROUP=${LOG_GROUP:-/ecs/fortexa-backend}

alarm() { aws cloudwatch put-metric-alarm --alarm-actions "$TOPIC" --ok-actions "$TOPIC" "$@"; echo "ok  $2"; }

# 1. No healthy backend behind the load balancer = the API is down.
alarm --alarm-name fortexa-backend-no-healthy-targets \
  --alarm-description "No healthy backend task behind fortexa-alb for 2 min: the API is down." \
  --namespace AWS/ApplicationELB --metric-name HealthyHostCount \
  --dimensions "Name=LoadBalancer,Value=$LB" "Name=TargetGroup,Value=$TG" \
  --statistic Minimum --period 60 --evaluation-periods 2 --threshold 1 \
  --comparison-operator LessThanThreshold --treat-missing-data breaching

# 2. A target failing health checks (crash loop, hung event loop).
alarm --alarm-name fortexa-backend-unhealthy-target \
  --alarm-description "A backend task has failed ALB health checks for 3 min." \
  --namespace AWS/ApplicationELB --metric-name UnHealthyHostCount \
  --dimensions "Name=LoadBalancer,Value=$LB" "Name=TargetGroup,Value=$TG" \
  --statistic Maximum --period 60 --evaluation-periods 3 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --treat-missing-data notBreaching

# 3. Server errors returned by the API.
alarm --alarm-name fortexa-backend-5xx \
  --alarm-description "More than 20 HTTP 5xx from the backend in 5 min, twice in a row." \
  --namespace AWS/ApplicationELB --metric-name HTTPCode_Target_5XX_Count \
  --dimensions "Name=LoadBalancer,Value=$LB" "Name=TargetGroup,Value=$TG" \
  --statistic Sum --period 300 --evaluation-periods 2 --threshold 20 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching

# 4. Application error lines. Every backend error log starts with "❌".
aws logs put-metric-filter --log-group-name "$LOG_GROUP" \
  --filter-name fortexa-backend-error-lines \
  --filter-pattern '"❌"' \
  --metric-transformations metricName=BackendErrorLines,metricNamespace=Fortexa/Backend,metricValue=1,defaultValue=0
echo "ok  metric filter fortexa-backend-error-lines"

alarm --alarm-name fortexa-backend-error-lines \
  --alarm-description "More than 50 error log lines in 10 min in $LOG_GROUP." \
  --namespace Fortexa/Backend --metric-name BackendErrorLines \
  --statistic Sum --period 600 --evaluation-periods 1 --threshold 50 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching

# 5. ECS running-task count. Needs Container Insights on fortexa-cluster (extra
#    CloudWatch cost, roughly US$1-3/month for one service), so it is opt-in:
#    CONTAINER_INSIGHTS=true. Alarms 1-2 already catch a dead API via the ALB.
if [ "${CONTAINER_INSIGHTS:-false}" = "true" ]; then
  alarm --alarm-name fortexa-backend-running-tasks \
    --alarm-description "fortexa-ec2-backend has had no running task for 2 min." \
    --namespace ECS/ContainerInsights --metric-name RunningTaskCount \
    --dimensions "Name=ClusterName,Value=fortexa-cluster" "Name=ServiceName,Value=fortexa-ec2-backend" \
    --statistic Minimum --period 60 --evaluation-periods 2 --threshold 1 \
    --comparison-operator LessThanThreshold --treat-missing-data breaching
fi

echo "Done. Verify: aws cloudwatch describe-alarms --alarm-name-prefix fortexa-backend"
