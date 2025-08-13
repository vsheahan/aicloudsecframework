# Contributing to AI Cloud Security Framework

Thank you for your interest in contributing! This framework provides production-ready security controls for AI agents across AWS, Azure, and GCP.

## How to Contribute

### 1. Report Issues or Propose Enhancements
- Use our [GitHub issue templates](.github/ISSUE_TEMPLATE/) for structured reporting
- **Bug reports**: For incorrect or missing framework guidance
- **Feature requests**: For new controls, cloud providers, or tools
- **Security issues**: For public security guidance improvements (use email for sensitive vulnerabilities)

### 2. Contribution Guidelines
- **Reference standards**: Link to NIST, ISO, or other security frameworks when proposing controls
- **Multi-cloud approach**: Provide implementations for AWS, Azure, and GCP when possible
- **Evidence-based**: Include concrete validation steps and evidence collection methods
- **Production-ready**: Ensure examples can be deployed and tested in real environments

### 3. Framework Structure
```
examples/           # Cloud-specific implementation guides
├── aws-notes.md    # Complete Terraform, CloudFormation, validation
├── azure-notes.md  # Terraform, ARM templates, Azure CLI
└── gcp-notes.md    # Terraform, Cloud Deployment Manager, gcloud

scripts/            # Validation and automation tools
├── validate-aws-controls.py   # Automated control validation
└── README.md       # Usage instructions for validation tools

docs/               # Framework documentation (00-overview through 60-governance)
templates/          # Reusable policy and configuration templates
mappings/           # Standards compliance mappings (CSV format)
```

## Current Good First Issues

### **Extend Validation Tooling**
- **Add Azure Control Validator**: Create Python script similar to `scripts/validate-aws-controls.py` for Azure
  - Expected: `scripts/validate-azure-controls.py` with az CLI integration
  - Validation: Check Managed Identity, Log Analytics, Network Security Groups
  - Acceptance: Color-coded output, JSON mode, CI/CD integration

- **Add GCP Control Validator**: Create validation script for GCP controls
  - Expected: `scripts/validate-gcp-controls.py` with gcloud integration  
  - Validation: Check Service Accounts, Cloud Logging, Firewall rules
  - Acceptance: Consistent interface with AWS/Azure validators

### **Expand Implementation Examples**
- **Add Kubernetes Deployment Manifests**: Secure K8s deployments for AI agents
  - Expected: Complete manifests in `examples/kubernetes/`
  - Include: Pod Security Standards, Network Policies, RBAC
  - Acceptance: Working examples with security controls A1-A6

- **Add Pulumi Examples**: Infrastructure as Code alternative to Terraform
  - Expected: Pulumi implementations for AWS/Azure/GCP controls
  - Location: `examples/pulumi/`
  - Acceptance: Equivalent functionality to existing Terraform examples

### **Enhance Documentation**
- **Add Implementation Case Study**: Real-world anonymized example
  - Expected: New doc showing before/after security posture
  - Include: Challenges faced, solutions implemented, lessons learned
  - Acceptance: Demonstrates practical framework value

- **Create Control Implementation Guides**: Step-by-step tutorials
  - Expected: Detailed guides for each control (A1-A6)
  - Include: Prerequisites, deployment steps, troubleshooting
  - Acceptance: Non-experts can follow successfully

### **Add New Cloud Providers**
- **Add Oracle Cloud Infrastructure (OCI)**: Expand multi-cloud coverage
  - Expected: `examples/oci-notes.md` with OCI-specific implementations
  - Include: Identity and Access Management, network controls, logging
  - Acceptance: Equivalent depth to AWS/Azure/GCP examples

- **Add Alibaba Cloud**: Implementation examples for Chinese cloud market
  - Expected: `examples/alibaba-notes.md` with Resource Access Management
  - Include: Terraform providers, CLI validation examples
  - Acceptance: Cultural and regional considerations documented

### **Security Enhancements**
- **Add Supply Chain Security Tools**: Implement Control A4 validation
  - Expected: Scripts to verify artifact signatures, SBOMs
  - Include: Sigstore integration, dependency scanning
  - Acceptance: Automated supply chain verification

- **Add Advanced Threat Detection**: Enhance Control A5 with ML-based detection
  - Expected: Integration with cloud-native security services
  - Include: Anomaly detection rules, automated response playbooks
  - Acceptance: Reduce false positives while maintaining security

## Development Workflow

1. **Fork and clone** the repository
2. **Create a feature branch** with descriptive name
3. **Follow existing patterns** in examples/ and scripts/
4. **Test your implementations** - ensure they actually work
5. **Document evidence collection** - show how to verify controls
6. **Submit pull request** with clear description of changes

## Code Quality Standards

### For Infrastructure Code
- **Tested**: All Terraform/ARM/CloudFormation should apply without errors
- **Secure**: Follow cloud security best practices
- **Documented**: Include deployment instructions and evidence collection
- **Tagged**: Use consistent resource tagging (Purpose, Control)

### For Validation Scripts
- **Automated**: Provide both pass/fail and detailed output
- **Consistent**: Follow interface pattern from existing validators
- **Robust**: Handle errors gracefully with helpful messages
- **Documented**: Include usage examples and CI/CD integration

### For Documentation
- **Clear**: Written for security practitioners, not just experts
- **Actionable**: Provide concrete steps and examples
- **Current**: Reference latest cloud service features and best practices
- **Evidence-based**: Show how to collect audit evidence

## Questions?

- **General questions**: Open a [GitHub Discussion](../../discussions)
- **Security concerns**: Email security reports per [SECURITY.md](SECURITY.md)
- **Bug reports**: Use our [bug report template](.github/ISSUE_TEMPLATE/bug_report.md)
- **Feature ideas**: Use our [feature request template](.github/ISSUE_TEMPLATE/feature_request.md)

## Recognition

Contributors will be acknowledged in release notes and our community recognizes contributions through:
- GitHub contributor graphs
- Mention in framework documentation
- Speaking opportunities at security conferences (with permission)

Thank you for helping make AI cloud security more accessible and effective!
