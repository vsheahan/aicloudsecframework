# AWS Notes
- Use IAM Roles Anywhere or OIDC federation for tool identities
- VPC endpoints for model APIs where available
- GuardDuty and CloudTrail Lake for forensic trails
- Bedrock Guardrails plus custom policy checks around tool calls

## AWS PrivateLink Setup for Model APIs

**Goal:** Ensure model API traffic stays on the AWS network and is not exposed to the public internet.

**Steps:**
1. Identify the model API endpoint service name (e.g., `com.amazonaws.vpce.us-east-1.<service>`).
2. Create an Interface VPC Endpoint in the orchestrator's VPC.
3. Associate appropriate security groups to allow only orchestrator subnets.
4. Enable private DNS integration for the endpoint.
5. Update the orchestrator application to resolve the API's private DNS name.
6. Validate with `dig` or `nslookup` that the resolved IP is within AWS private ranges.
7. Test API calls from the orchestrator to confirm private connectivity.

**Evidence:**
- Endpoint ID and DNS name
- Security group rules
- Screenshot or log of successful private API call

---

## Control A1: IAM Role for AI Agent (15-minute sessions)

```hcl
# AI Agent IAM Role with short-lived sessions
resource "aws_iam_role" "ai_agent_role" {
  name = "ai-agent-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      }
    ]
  })

  max_session_duration = 900 # 15 minutes maximum
  
  tags = {
    Purpose = "AI-Agent-Identity"
    Control = "A1"
  }
}

# Least privilege policy for AI agent
resource "aws_iam_policy" "ai_agent_policy" {
  name = "ai-agent-least-privilege"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude*",
          "arn:aws:s3:::${var.approved_data_bucket}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ai_agent_policy_attachment" {
  role       = aws_iam_role.ai_agent_role.name
  policy_arn = aws_iam_policy.ai_agent_policy.arn
}
```

## Control A2: Tool Budget and Policy Guards

```hcl
# DynamoDB table for tracking tool usage and budgets
resource "aws_dynamodb_table" "tool_usage_tracking" {
  name           = "ai-tool-usage-tracking"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "session_id"
  range_key      = "tool_name"

  attribute {
    name = "session_id"
    type = "S"
  }
  
  attribute {
    name = "tool_name"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Purpose = "AI-Tool-Budget-Tracking"
    Control = "A2"
  }
}

# Lambda function for budget enforcement
resource "aws_lambda_function" "budget_enforcer" {
  filename         = "budget_enforcer.zip"
  function_name    = "ai-tool-budget-enforcer"
  role            = aws_iam_role.budget_enforcer_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 30

  environment {
    variables = {
      USAGE_TABLE = aws_dynamodb_table.tool_usage_tracking.name
      MAX_SESSION_SPEND = "50.00"
      MAX_DAILY_SPEND = "500.00"
    }
  }

  tags = {
    Purpose = "AI-Tool-Budget-Enforcement"
    Control = "A2"
  }
}
```

## Control A5: CloudTrail Logging for Forensics

```hcl
# S3 bucket for immutable audit logs
resource "aws_s3_bucket" "audit_logs" {
  bucket = "ai-agent-audit-logs-${random_id.bucket_suffix.hex}"
  
  tags = {
    Purpose = "AI-Agent-Audit-Logs"
    Control = "A5"
  }
}

resource "aws_s3_bucket_versioning" "audit_logs_versioning" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs_encryption" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudTrail for API activity logging
resource "aws_cloudtrail" "ai_agent_trail" {
  name           = "ai-agent-activity-trail"
  s3_bucket_name = aws_s3_bucket.audit_logs.bucket
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::Bedrock::*"
      values = ["arn:aws:bedrock:*"]
    }
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${var.approved_data_bucket}/*"]
    }
  }

  tags = {
    Purpose = "AI-Agent-Activity-Logging"
    Control = "A5"
  }
}
```

## Control A6: Egress Controls and Cost Monitoring

```hcl
# VPC with restricted egress
resource "aws_vpc" "ai_agent_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name    = "ai-agent-vpc"
    Purpose = "AI-Agent-Network-Isolation"
    Control = "A6"
  }
}

# Network ACL with egress allow-list
resource "aws_network_acl" "egress_allowlist" {
  vpc_id = aws_vpc.ai_agent_vpc.id

  # Allow traffic to AWS Bedrock endpoints
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"  # AWS service endpoints
    from_port  = 443
    to_port    = 443
  }

  # Allow DNS resolution
  egress {
    protocol   = "udp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 53
    to_port    = 53
  }

  # Deny all other egress
  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name    = "ai-agent-egress-allowlist"
    Purpose = "AI-Agent-Egress-Control"
    Control = "A6"
  }
}

# Cost anomaly detection
resource "aws_ce_anomaly_detector" "ai_agent_cost_anomaly" {
  name         = "ai-agent-cost-anomaly"
  monitor_type = "DIMENSIONAL"

  specification = jsonencode({
    Dimension = "SERVICE"
    MatchOptions = ["EQUALS"]
    Values = ["Amazon Bedrock", "Amazon ECS"]
  })

  tags = {
    Purpose = "AI-Agent-Cost-Monitoring"
    Control = "A6"
  }
}

resource "aws_ce_anomaly_subscription" "ai_agent_cost_alerts" {
  name      = "ai-agent-cost-alerts"
  frequency = "DAILY"
  
  monitor_arn_list = [
    aws_ce_anomaly_detector.ai_agent_cost_anomaly.arn
  ]
  
  subscriber {
    type    = "EMAIL"
    address = var.security_team_email
  }

  threshold_expression {
    and {
      dimension {
        key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
        values        = ["100"]
        match_options = ["GREATER_THAN_OR_EQUAL"]
      }
    }
  }

  tags = {
    Purpose = "AI-Agent-Cost-Alerting"
    Control = "A6"
  }
}
```

## Variables and Outputs

```hcl
# variables.tf
variable "aws_region" {
  description = "AWS region for AI agent deployment"
  type        = string
  default     = "us-east-1"
}

variable "approved_data_bucket" {
  description = "S3 bucket containing approved data for AI agents"
  type        = string
}

variable "security_team_email" {
  description = "Email for security alerts and cost anomalies"
  type        = string
}

# outputs.tf
output "ai_agent_role_arn" {
  description = "ARN of the AI agent IAM role"
  value       = aws_iam_role.ai_agent_role.arn
}

output "audit_logs_bucket" {
  description = "S3 bucket for audit logs"
  value       = aws_s3_bucket.audit_logs.bucket
}

output "vpc_id" {
  description = "VPC ID for AI agent deployment"
  value       = aws_vpc.ai_agent_vpc.id
}
```

## Deployment Instructions

```bash
# 1. Initialize Terraform
terraform init

# 2. Set required variables
export TF_VAR_approved_data_bucket="your-approved-data-bucket"
export TF_VAR_security_team_email="security@yourcompany.com"

# 3. Plan deployment
terraform plan

# 4. Apply with approval
terraform apply

# 5. Verify controls are working
aws sts assume-role --role-arn $(terraform output -raw ai_agent_role_arn) \
  --role-session-name test-session \
  --duration-seconds 900
```

## Evidence Collection

After deployment, collect evidence for each control:

**A1 Identity Evidence:**
```bash
# Verify 15-minute session limit
aws iam get-role --role-name ai-agent-execution-role | jq '.Role.MaxSessionDuration'

# Test role assumption
aws sts assume-role --role-arn $(terraform output -raw ai_agent_role_arn) \
  --role-session-name evidence-collection \
  --duration-seconds 900
```

**A5 Logging Evidence:**
```bash
# Verify CloudTrail is logging Bedrock calls
aws logs describe-log-groups --log-group-name-prefix aws/bedrock

# Check audit log bucket
aws s3 ls $(terraform output -raw audit_logs_bucket)
```

**A6 Network Evidence:**
```bash
# Verify network ACL rules
aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$(terraform output -raw vpc_id)"

# Test egress restrictions (should fail for non-approved destinations)
curl -I https://example.com  # Should timeout or fail
```

---

## CloudFormation Alternative

For teams preferring CloudFormation, here's the equivalent template for Control A1:

```yaml
# cloudformation/ai-agent-iam.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'AI Agent IAM Role with 15-minute sessions (Control A1)'

Parameters:
  ApprovedDataBucket:
    Type: String
    Description: S3 bucket containing approved data for AI agents
  AWSRegion:
    Type: String
    Default: !Ref AWS::Region
    Description: AWS region for deployment

Resources:
  AIAgentExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ai-agent-execution-role
      MaxSessionDuration: 900  # 15 minutes
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ecs-tasks.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                'aws:RequestedRegion': !Ref AWSRegion
      Tags:
        - Key: Purpose
          Value: AI-Agent-Identity
        - Key: Control
          Value: A1

  AIAgentPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: ai-agent-least-privilege
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - bedrock:InvokeModel
              - s3:GetObject
            Resource:
              - !Sub 'arn:aws:bedrock:${AWSRegion}::foundation-model/anthropic.claude*'
              - !Sub '${ApprovedDataBucket}/*'
      Roles:
        - !Ref AIAgentExecutionRole

Outputs:
  AIAgentRoleArn:
    Description: ARN of the AI agent IAM role
    Value: !GetAtt AIAgentExecutionRole.Arn
    Export:
      Name: !Sub '${AWS::StackName}-AIAgentRoleArn'
```

**Deploy CloudFormation:**
```bash
aws cloudformation create-stack \
  --stack-name ai-agent-security \
  --template-body file://cloudformation/ai-agent-iam.yaml \
  --parameters ParameterKey=ApprovedDataBucket,ParameterValue=your-approved-data-bucket \
  --capabilities CAPABILITY_NAMED_IAM
```
