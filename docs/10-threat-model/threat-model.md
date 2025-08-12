# Threat Model for Agentic AI in Cloud

## Assets
- Knowledge bases and embeddings
- Training data, RLHF datasets
- Model weights and system prompts
- Tool credentials and action authorizations
- Inference traffic and logs
- Customer data and proprietary code

## Adversaries
- Prompt injection attackers
- Supply chain adversaries in model, package, or dataset
- Malicious tool providers or compromised plugins
- Rogue insiders and over-privileged services
- External APT with cloud footholds

## Attack Surfaces and Scenarios
- **Injection and Indirect Prompting**: Model coerced to execute harmful tools or exfiltrate secrets.
- **Tool Abuse and Action Hijacking**: Agent invokes cloud, SaaS, or payment APIs beyond policy.
- **Data Leakage**: Retrieval layer returns sensitive documents through weak filters or bad access control.
- **Supply Chain Poisoning**: Weights, datasets, or embeddings tampered with in transit or at rest.
- **Egress and Exfiltration**: Unrestricted outbound to untrusted domains or shadow storage.
- **Cost and Resource Drain**: Unbounded tool use, infinite loops, or query storms.

## STRIDE Mapping
- Spoofing: Weak identity and token management for tools and agents
- Tampering: Dataset and weight integrity
- Repudiation: Insufficient logging or signed actions
- Information Disclosure: Retrieval, logging, telemetry
- Denial of Service: Tool loops and unbounded agent recursion
- Elevation of Privilege: Over-broad roles or cross-tenant jumps

## Trust Boundaries
- User <> Frontend
- Frontend <> Orchestrator
- Orchestrator <> Tools/Plugins
- Orchestrator <> Model API
- Orchestrator <> Vector DB and Data Lake
- Cloud VPCs/VNETs <> Public Internet

See `docs/20-architectures/` for reference diagrams.
