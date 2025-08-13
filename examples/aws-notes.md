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

## Terraform Egress Allow-List (Stub)

```hcl
# Restrict outbound traffic to only approved domains or IP ranges
resource "aws_network_acl" "egress_allowlist" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "203.0.113.0/24" # Replace with approved CIDR or endpoint
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "egress-allowlist"
  }
}
```

**Notes:**
- Replace `203.0.113.0/24` with the specific CIDR blocks of approved destinations.
- For HTTPS-based model APIs, consider using AWS Network Firewall or DNS filtering to enforce FQDN-based allow-lists.
- Reference Control A6 in `docs/30-controls/controls-catalog.md` for mapping.
