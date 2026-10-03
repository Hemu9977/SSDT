#!/bin/bash
# CloudWatch alarms for the Fortexa EC2 Valkey. Idempotent (put-metric-alarm upserts).
#   INSTANCE_ID=i-... bash infrastructure/redis-ec2/create-alarms.sh
#
# Stage A (always running): ValkeyUp treats missing data as BREACHING — no data means
# the instance or its metrics script is dead. Stage B (stop/start) must switch it to
# notBreaching, because a deliberately stopped instance publishes nothing.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1
I=${INSTANCE_ID:?set INSTANCE_ID}
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
TOPIC="arn:aws:sns:${AWS_REGION}:${ACCOUNT}:fortexa-redis-alerts"
NS=Fortexa/Redis
DIM="Name=InstanceId,Value=$I"

alarm() { aws cloudwatch put-metric-alarm --alarm-actions "$TOPIC" --ok-actions "$TOPIC" "$@"; echo "ok  $2"; }

aws cloudwatch put-metric-alarm --alarm-name fortexa-redis-system-status-failed \
  --alarm-description "Host/AWS-side failure. Action: EC2 recover (same ID, IP, EBS) + notify." \
  --namespace AWS/EC2 --metric-name StatusCheckFailed_System --dimensions "$DIM" \
  --statistic Maximum --period 60 --evaluation-periods 2 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "arn:aws:automate:${AWS_REGION}:ec2:recover" "$TOPIC" --ok-actions "$TOPIC"
echo "ok  fortexa-redis-system-status-failed"

aws cloudwatch put-metric-alarm --alarm-name fortexa-redis-instance-status-failed \
  --alarm-description "OS unresponsive for 5 min. Action: reboot + notify (Valkey restarts from AOF)." \
  --namespace AWS/EC2 --metric-name StatusCheckFailed_Instance --dimensions "$DIM" \
  --statistic Maximum --period 60 --evaluation-periods 5 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "arn:aws:automate:${AWS_REGION}:ec2:reboot" "$TOPIC" --ok-actions "$TOPIC"
echo "ok  fortexa-redis-instance-status-failed"

alarm --alarm-name fortexa-redis-valkey-down \
  --alarm-description "Valkey does not answer PING over TLS on the instance for 3 min (process, TLS or ACL broken), or no metrics at all." \
  --namespace $NS --metric-name ValkeyUp --dimensions "$DIM" \
  --statistic Minimum --period 60 --evaluation-periods 3 --threshold 1 --comparison-operator LessThanThreshold \
  --treat-missing-data breaching

alarm --alarm-name fortexa-redis-memory-high \
  --alarm-description "Valkey used_memory above 75% of maxmemory. Policy is noeviction: at 100% writes (scans) fail." \
  --namespace $NS --metric-name MemoryUsedPercentOfMax --dimensions "$DIM" \
  --statistic Maximum --period 60 --evaluation-periods 5 --threshold 75 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

alarm --alarm-name fortexa-redis-host-memory-high \
  --alarm-description "Host RAM above 90% for 10 min (AOF rewrite / RDB fork needs headroom)." \
  --namespace $NS --metric-name mem_used_percent --dimensions "$DIM" \
  --statistic Average --period 60 --evaluation-periods 10 --threshold 90 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

alarm --alarm-name fortexa-redis-disk-high \
  --alarm-description "Root volume above 80% (AOF/RDB live here)." \
  --namespace $NS --metric-name disk_used_percent --dimensions "$DIM" \
  --statistic Maximum --period 300 --evaluation-periods 1 --threshold 80 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

aws cloudwatch put-metric-alarm --alarm-name fortexa-redis-persistence-failing \
  --alarm-description "Last AOF write or RDB save failed (disk full / IO error): durability lost." \
  --metrics "[{\"Id\":\"aof\",\"MetricStat\":{\"Metric\":{\"Namespace\":\"$NS\",\"MetricName\":\"AofLastWriteOk\",\"Dimensions\":[{\"Name\":\"InstanceId\",\"Value\":\"$I\"}]},\"Period\":60,\"Stat\":\"Minimum\"},\"ReturnData\":false},
             {\"Id\":\"rdb\",\"MetricStat\":{\"Metric\":{\"Namespace\":\"$NS\",\"MetricName\":\"RdbLastBgsaveOk\",\"Dimensions\":[{\"Name\":\"InstanceId\",\"Value\":\"$I\"}]},\"Period\":60,\"Stat\":\"Minimum\"},\"ReturnData\":false},
             {\"Id\":\"ok\",\"Expression\":\"MIN([aof, rdb])\",\"Label\":\"persistence ok\",\"ReturnData\":true}]" \
  --evaluation-periods 3 --threshold 1 --comparison-operator LessThanThreshold --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC" --ok-actions "$TOPIC"
echo "ok  fortexa-redis-persistence-failing"

# t4g runs in 'unlimited' mode and launches with 0 credits, so a low CPUCreditBalance is
# normal and free. What matters is CPU held above the 20% baseline, which is when
# surplus credits start being charged.
alarm --alarm-name fortexa-redis-cpu-above-baseline \
  --alarm-description "CPU above the t4g.small 20% baseline for 1 h: unexpected load, and unlimited-mode surplus charges." \
  --namespace AWS/EC2 --metric-name CPUUtilization --dimensions "$DIM" \
  --statistic Average --period 300 --evaluation-periods 12 --threshold 20 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching

alarm --alarm-name fortexa-redis-cert-expiring \
  --alarm-description "Valkey server certificate expires in < 30 days. Re-issue with the offline CA, update fortexa-redis/host, restart valkey." \
  --namespace $NS --metric-name CertDaysLeft --dimensions "$DIM" \
  --statistic Minimum --period 3600 --evaluation-periods 1 --threshold 30 --comparison-operator LessThanThreshold \
  --treat-missing-data notBreaching

# Backend-side view: repeated reconnects mean the app cannot reach Redis.
aws logs put-metric-filter --log-group-name /ecs/fortexa-backend --filter-name fortexa-redis-reconnecting \
  --filter-pattern '"[Redis] Reconnecting"' \
  --metric-transformations metricName=BackendRedisReconnecting,metricNamespace=$NS,metricValue=1,unit=Count
alarm --alarm-name fortexa-redis-backend-reconnecting \
  --alarm-description "Backend logged more than 10 '[Redis] Reconnecting' lines in 5 min: the app cannot reach Redis." \
  --namespace $NS --metric-name BackendRedisReconnecting \
  --statistic Sum --period 300 --evaluation-periods 1 --threshold 10 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching
