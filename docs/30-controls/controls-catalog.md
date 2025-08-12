# Controls Catalog

Each control includes intent, implementation guidance, evidence, and mapping to standards.

## A1. Identity for Agents and Tools
- **Intent**: Bind every agent and tool to first-class cloud identity with least privilege and short TTL tokens.
- **Implement**: Use workload identity federation, scoped IAM roles, per-action permission sets, just-in-time credentials.
- **Evidence**: IAM policy docs, token TTL configs, role assumption logs.
- **Mappings**: NIST AC-2, AC-6; ISO 27001 A.5.15, A.8.2; SOC2 CC6.x

## A2. Tool Policy and Budget Guards
- **Intent**: Constrain what tools can do, where, and how often.
- **Implement**: Allow lists, rate limits, per-session budgets, human-in-the-loop for irreversible actions.
- **Evidence**: Policy definitions, enforcement logs, break-glass approvals.
- **Mappings**: NIST CM-7, AU-12; ISO 27001 A.8.16; SOC2 CC7.x

## A3. Retrieval Safety
- **Intent**: Prevent sensitive data leakage via retrieval.
- **Implement**: ABAC on documents, content classification, DLP filters, semantic redaction.
- **Evidence**: Classifier configs, DLP rules, retrieval audit logs.
- **Mappings**: NIST SC-7, MP-5; ISO 27001 A.8.12; SOC2 CC8.x

## A4. Supply Chain Integrity
- **Intent**: Assure integrity of datasets, weights, prompts, and packages.
- **Implement**: Signed artifacts, checksums, provenance metadata, SBOMs.
- **Evidence**: Sigstore logs, SBOMs, attestation records.
- **Mappings**: NIST SI-7, SA-12; ISO 27001 A.5.23; SOC2 CC1.2

## A5. Observation and Forensics
- **Intent**: End to end trace of agent decisions and tool actions.
- **Implement**: Request signing, structured logs, heatmap of tool use, immutable storage, privacy controls.
- **Evidence**: Log schemas, retention configs, sample traces.
- **Mappings**: NIST AU-2, AU-12; ISO 27001 A.8.15; SOC2 CC3.x

## A6. Egress and Cost Controls
- **Intent**: Block exfiltration and runaway spend.
- **Implement**: Egress allow-lists, DNS filtering, NAT policies, per-session spend caps.
- **Evidence**: Firewall rules, cost anomaly alerts.
- **Mappings**: NIST SC-7, AU-6; ISO 27001 A.8.7; SOC2 CC6.6
