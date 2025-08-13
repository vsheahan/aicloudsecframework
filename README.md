# aicloudsecframework

A practical, open framework for securing agentic AI systems on AWS, Azure, and GCP. It gives you reference architectures, a prescriptive controls catalog, assurance tests, and audit-ready mappings to NIST, ISO, and SOC 2 so you can ship safely with evidence.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
![Status: v0.1.0](https://img.shields.io/badge/status-v0.1.0-informational)
![PRs: welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

---

## What is inside

- **Reference architectures** with guardrails for inference, RAG, and fine tuning  
- **Controls catalog** with intent, implementation, evidence, and standards mappings  
- **Assurance guidance** with adversarial tests and acceptance criteria  
- **Operations runbooks** for incident response, monitoring, and cost control  
- **Governance policies** for registries, change control, and telemetry privacy  
- **Templates** for model cards, tool policies, and release risk attestations

## Who this is for

Security architects, platform teams, AI engineering leads, and auditors who need practical controls that map to real evidence.

## Quick start

1. Read the overview: `docs/00-overview/overview.md`  
2. Pick a reference pattern: `docs/20-architectures/reference-architectures.md`  
3. Implement controls A1 to A6: `docs/30-controls/controls-catalog.md`  
4. Run the assurance tests and capture evidence: `docs/40-assurance/assurance.md`  
5. Operationalize with the runbooks: `docs/50-operations/runbooks.md`

## Standards mapping

Use `mappings/controls-matrix.csv` to track ownership, status, and evidence. Mapped to NIST CSF, NIST 800-53, ISO 27001, ISO 27017, ISO 27018, ISO 27701, and SOC 2.

## Roadmap

- v0.2 - provider walkthroughs, request signing example, baseline eval suite  
- v0.3 - red team harness, evidence automation, CNAPP integrations

## Contributing

PRs are welcome. See `CONTRIBUTING.md` for style and `SECURITY.md` for vulnerability reporting. Good first issues are labeled in GitHub.

## License and attribution

Licensed under the Apache License, Version 2.0. See `LICENSE`.  
Attribution notices are in `NOTICE`.

## Version and Scope

**Version:** 0.1.0  
**Date:** 2025-08-12

### Scope
- Cloud hosted LLMs and agentic orchestration
- First party and third party tools, plugins, and external actions
- Training, fine-tuning, RAG, and online inference
- Multi cloud and hybrid patterns, with emphasis on AWS, Azure, and GCP
