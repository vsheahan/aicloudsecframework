# Security Policy

## Reporting Security Vulnerabilities

We take security issues seriously. If you discover a security vulnerability in this framework or its examples, please report it responsibly.

### How to Report

**Please do NOT create a public GitHub issue for security vulnerabilities.**

Instead, please email security reports to: **vsheahan+security@gmail.com**

Include the following information in your report:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Assessment**: We will assess the vulnerability and determine severity within 5 business days
- **Resolution**: We will work to address confirmed vulnerabilities promptly
- **Disclosure**: We will coordinate responsible disclosure with you

### Scope

This security policy covers:
- Framework documentation and guidance that could lead to insecure implementations
- Example configurations, Terraform code, and scripts in this repository
- Template files that could introduce security weaknesses when used

### Out of Scope

This policy does not cover:
- Third-party tools, cloud services, or dependencies referenced by the framework
- Security issues in implementations based on this framework (unless directly caused by framework guidance)
- General security questions or consulting requests

### Security Best Practices

When implementing this framework:
- Always review and customize examples before production use
- Follow the principle of least privilege in all configurations
- Regularly update dependencies and cloud service configurations
- Conduct security reviews of your specific implementation
- Test controls in non-production environments first

### Framework Security Considerations

This framework provides security guidance for AI agents in cloud environments. While we strive for accuracy and completeness:

- **Guidance Nature**: This framework provides recommendations, not guaranteed security
- **Context Dependent**: Security controls must be adapted to your specific environment
- **Evolving Landscape**: AI security is rapidly evolving; regularly review and update implementations
- **Professional Review**: Consider professional security review for critical implementations

### Supported Versions

We provide security updates for:
- The current main branch
- The most recent release tag

### Security Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who help improve the framework's security (with permission).

---

For general questions about the framework, please use GitHub Issues or Discussions rather than the security email.