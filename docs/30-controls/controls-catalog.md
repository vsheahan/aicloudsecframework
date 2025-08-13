# Controls Catalog

Each control includes intent, implementation guidance, evidence, and mapping to standards.

## A1. Identity for Agents and Tools
- **Intent**: Bind every agent and tool to first-class cloud identity with least privilege and short TTL tokens.
- **Implement**: Use workload identity federation, scoped IAM roles, per-action permission sets, just-in-time credentials.
- **Evidence**: IAM policy docs, token TTL configs, role assumption logs.
- **Mappings**: NIST AC-2, AC-6; ISO 27001 A.5.15, A.8.2; ISO/IEC 42001 5.4.2, 6.3.3; SOC2 CC6.x

### Check
Every tool or agent identity uses short-lived credentials (≤ 15 minutes) and least-privilege policies.
**Evidence:** IAM/Managed Identity config; AssumeRole/GetToken logs showing `SessionDuration <= 900s`.

## A2. Tool Policy and Budget Guards
- **Intent**: Constrain what tools can do, where, and how often.
- **Implement**: Allow lists, rate limits, per-session budgets, human-in-the-loop for irreversible actions.
- **Evidence**: Policy definitions, enforcement logs, break-glass approvals.
- **Mappings**: NIST CM-7, AU-12; ISO 27001 A.8.16; ISO/IEC 42001 6.3.4; SOC2 CC7.x

### Check
Each tool has an explicit allow-list of actions and a per-session budget; irreversible actions require human approval.
**Evidence:** Policy JSON; enforcement log showing denied over-budget attempt and approval workflow records.

## A3. Retrieval Safety
- **Intent**: Prevent sensitive data leakage via retrieval.
- **Implement**: ABAC on documents, content classification, DLP filters, semantic redaction.
- **Evidence**: Classifier configs, DLP rules, retrieval audit logs.
- **Mappings**: NIST SC-7, MP-5; ISO 27001 A.8.12; ISO/IEC 42001 6.4.2, 6.5.3; SOC2 CC8.x

### Check
Sensitive content is classified and filtered before retrieval; access governed by ABAC tied to user/project.
**Evidence:** Classifier configuration; DLP rule IDs; retrieval audit log with subject attributes.

## A4. Supply Chain Integrity
- **Intent**: Assure integrity of datasets, weights, prompts, and packages.
- **Implement**: Signed artifacts, checksums, provenance metadata, SBOMs.
- **Evidence**: Sigstore logs, SBOMs, attestation records.
- **Mappings**: NIST SI-7, SA-12; ISO 27001 A.5.23; ISO/IEC 42001 6.4.5, 6.5.5; SOC2 CC1.2

### Check
All datasets, weights, and packages are signed and verified at pull; SBOMs present for tools and images.
**Evidence:** Sigstore/Rekor entries; checksum records; SBOM artifacts in repository.

## A5. Observation and Forensics
- **Intent**: End to end trace of agent decisions and tool actions.
- **Implement**: Request signing, structured logs, heatmap of tool use, immutable storage, privacy controls.
- **Evidence**: Log schemas, retention configs, sample traces.
- **Mappings**: NIST AU-2, AU-12; ISO 27001 A.8.15; ISO/IEC 42001 6.6.3; SOC2 CC3.x

### Check
All agent requests and tool actions are signed and traceable end to end; logs are immutable and access-controlled.
**Evidence:** Log schema samples; retention configs; example trace with request ID and signature.

## A6. Egress and Cost Controls
- **Intent**: Block exfiltration and runaway spend.
- **Implement**: Egress allow-lists, DNS filtering, NAT policies, per-session spend caps.
- **Evidence**: Firewall rules, cost anomaly alerts.
- **Mappings**: NIST SC-7, AU-6; ISO 27001 A.8.7; ISO/IEC 42001 6.5.4, 6.6.4; SOC2 CC6.6

### Check
Outbound traffic restricted to an allow-list of destinations; per-session and per-tenant spend caps enforced.
**Evidence:** Firewall/NAT policy; DNS filter config; cost anomaly alert with threshold and action taken.
