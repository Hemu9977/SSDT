#!/bin/bash
# Launches the Fortexa EC2 Valkey instance. Prerequisites (see README.md):
#   - security group fortexa-redis-ec2-sg, instance profile fortexa-redis-instance-role
#   - secrets fortexa-redis/host and fortexa-redis/app (create-secrets.sh)
#   - private zone fortexa.internal with redis.fortexa.internal -> PRIVATE_IP
#
#   bash infrastructure/redis-ec2/launch-instance.sh
set -euo pipefail
cd "$(dirname "$0")"
export AWS_PROFILE=${AWS_PROFILE:-ssdt-profile}
export AWS_REGION=${AWS_REGION:-ap-northeast-1}
export AWS_PAGER=""
export MSYS_NO_PATHCONV=1

INSTANCE_TYPE=${INSTANCE_TYPE:-t4g.small}
SUBNET_ID=${SUBNET_ID:-subnet-014a7ae2b498c12d3}        # fortexa-subnet-private1-ap-northeast-1a
PRIVATE_IP=${PRIVATE_IP:-10.0.128.50}                     # must match the A record and the cert SAN
SG_NAME=${SG_NAME:-fortexa-redis-ec2-sg}
PROFILE_NAME=${PROFILE_NAME:-fortexa-redis-instance-role}
NAME=${NAME:-fortexa-redis-1}
AMI_ID=${AMI_ID:-$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 --query Parameter.Value --output text)}
SG_ID=$(aws ec2 describe-security-groups --filters Name=group-name,Values="$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)

aws secretsmanager describe-secret --secret-id fortexa-redis/host >/dev/null \
  || { echo "fortexa-redis/host does not exist yet — run create-secrets.sh first" >&2; exit 1; }

UD=$(mktemp)
trap 'rm -f "$UD"' EXIT
bash build-user-data.sh > "$UD"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) UDW=$(cygpath -m "$UD") ;; *) UDW="$UD" ;; esac

echo "ami=$AMI_ID type=$INSTANCE_TYPE subnet=$SUBNET_ID ip=$PRIVATE_IP sg=$SG_ID" >&2
aws ec2 run-instances \
  --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" --count 1 \
  --subnet-id "$SUBNET_ID" --private-ip-address "$PRIVATE_IP" --security-group-ids "$SG_ID" \
  --no-associate-public-ip-address \
  --iam-instance-profile Name="$PROFILE_NAME" \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled,InstanceMetadataTags=disabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=10,VolumeType=gp3,Encrypted=true,DeleteOnTermination=false}' \
  --credit-specification CpuCredits=unlimited \
  --maintenance-options AutoRecovery=default \
  --disable-api-termination \
  --disable-api-stop \
  --user-data "file://$UDW" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=App,Value=fortexa},{Key=Role,Value=redis}]" \
    "ResourceType=volume,Tags=[{Key=Name,Value=$NAME-root},{Key=App,Value=fortexa},{Key=Role,Value=redis}]" \
    "ResourceType=network-interface,Tags=[{Key=Name,Value=$NAME},{Key=App,Value=fortexa},{Key=Role,Value=redis}]" \
  --query 'Instances[0].InstanceId' --output text
