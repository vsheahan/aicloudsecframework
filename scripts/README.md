# Validation Scripts

This directory contains scripts to validate implementation of the AI Security Framework controls.

## AWS Control Validator

The `validate-aws-controls.py` script automatically checks AWS resources for compliance with controls A1-A6.

### Installation

```bash
pip install boto3 colorama
```

### Usage

```bash
# Basic validation with default profile
python3 validate-aws-controls.py

# Use specific AWS profile and region
python3 validate-aws-controls.py --profile my-aws-profile --region us-west-2

# JSON output for automation
python3 validate-aws-controls.py --output json
```

### What It Validates

**Control A1 - Identity for Agents and Tools:**
- ✅ IAM role session duration ≤ 15 minutes
- ✅ Proper control tagging
- ✅ Assume role policy conditions

**Control A2 - Tool Policy and Budget Guards:**
- ✅ DynamoDB budget tracking table exists
- ✅ TTL enabled for session cleanup
- ✅ Proper table schema (session_id, tool_name)

**Control A5 - Observation and Forensics:**
- ✅ CloudTrail configured and logging
- ✅ Bedrock data events captured
- ✅ Audit logs bucket with encryption
- ✅ Bucket versioning enabled

**Control A6 - Egress and Cost Controls:**
- ✅ AI agent VPC exists
- ✅ Restrictive Network ACLs
- ⚠️ Cost anomaly detection (manual verification)

**Controls A3 & A4:**
- ⚠️ Manual verification required for data classification and supply chain

### Exit Codes

- `0`: All automated checks passed
- `1`: One or more controls failed validation
- `2`: Fatal error during validation

### Example Output

```
AWS AI Security Framework Control Validator
Region: us-east-1
Timestamp: 2024-01-15T10:30:00

═══ Control A1: Identity for Agents and Tools ═══
✓ PASS: IAM role session duration: 900s (≤15 minutes)
✓ PASS: IAM role properly tagged with Control: A1
✓ PASS: Assume role policy includes security conditions

═══ Control A2: Tool Policy and Budget Guards ═══
✓ PASS: DynamoDB TTL enabled for session cleanup
✓ PASS: Budget tracking table has session_id hash key
✓ PASS: Budget tracking table has tool_name range key

═══ VALIDATION SUMMARY ═══
✓ Control A1: PASS
✓ Control A2: PASS
⚠ Control A3: MANUAL
⚠ Control A4: MANUAL
✓ Control A5: PASS
✓ Control A6: PASS

OVERALL: PASSED - All automated checks successful
```

## Integration with CI/CD

Add the validator to your CI/CD pipeline:

```yaml
# .github/workflows/security-validation.yml
- name: Validate AI Security Controls
  run: |
    pip install boto3 colorama
    python3 scripts/validate-aws-controls.py --output json > validation-results.json
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```