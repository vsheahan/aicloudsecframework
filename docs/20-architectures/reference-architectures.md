# Reference Architectures

## 1. Minimal Secure Inference with Tooling
```mermaid
flowchart LR
  U[User] --> FE[Frontend]
  FE --> GW[API Gateway + WAF]
  GW --> ORCH[Agent Orchestrator]
  ORCH --> LLM[Model API]
  ORCH --> TOOLS[Tool Proxy]
  TOOLS --> P1[Cloud API Wrapper]
  TOOLS --> SaaS[SaaS Connectors]
  ORCH --> VDB[Vector DB]
  VDB --> S3[(Data Lake)]
  subgraph Cloud Network
    ORCH
    TOOLS
    VDB
    LLM
  end
```
**Controls**
- Per tool scoped, short lived credentials
- Policy guardrails with allow-list actions and budgets
- Egress allow-list at NAT or firewall
- Inference request signing and audit trails

## 2. RAG with Sensitive Corpora
```mermaid
flowchart LR
  SCR[Source Repos] --> PIPE[Ingestion Pipeline]
  PIPE --> CLASS[PII Classifier]
  CLASS --> DLP[DLP Filters]
  DLP --> ENC[Envelope Encryption]
  ENC --> VDB[Vector DB Private]
  FE --> GW --> ORCH --> VDB
  ORCH --> LLM
```
**Controls**
- Attribute based access control on documents
- Semantic filtering and content rules before retrieval
- Tenant and project isolation in VDB
- Cryptographic integrity checks on embeddings

## 3. Fine Tuning in Isolated Enclave
```mermaid
flowchart LR
  RAW[Raw Data] --> CUR[Curated Sets]
  CUR --> FT[Fine Tune Job]
  FT --> REG[Model Registry]
  REG --> DEP[Deployer]
  DEP --> ORCH
  subgraph Secure Enclave
    FT
    REG
  end
```
**Controls**
- Data use approvals and lineage
- Reproducible training manifests
- Model cards and risk attestations
- Registry with signed artifacts
