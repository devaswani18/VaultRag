# Security Policy

VaultRAG is committed to delivering a secure, tamper-evident, multi-tenant RAG platform. We take security vulnerabilities seriously and appreciate responsible disclosure from researchers and the community.

---

## Supported Versions

Only the latest release running on the `main` branch receives active security updates and patches.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main`           | :white_check_mark: |
| Older releases   | :x:                |

---

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

If you discover a potential vulnerability in VaultRAG, report it privately through one of the following methods:

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   - Navigate to the [VaultRAG Security Advisory tab](https://github.com/devaswani18/VaultRag/security/advisories/new) and submit a private report.
2. **Email**:
   - Send encrypted or plain details to `security@vaultrag.dev` (or the project maintainer at `devaswani18@gmail.com`).

### What to Include in Your Report

To help us triage and investigate efficiently, please include:
- A clear description of the vulnerability and its potential impact.
- Affected components (e.g., API router, Auth verifier, Ingestion pipeline, Hashchain, CloudFront CSP, Frontend).
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- Any potential remediations or mitigation suggestions.

---

## Response Process & SLA

When a report is received, the maintainers will:

1. **Acknowledgement**: Acknowledge receipt within **48 hours**.
2. **Triage & Assessment**: Validate the vulnerability and assign a CVSS severity rating within **5 business days**.
3. **Remediation & Patching**:
   - **Critical / High**: Targeted fix within **7–14 days**.
   - **Medium / Low**: Targeted fix within **30 days**.
4. **Public Disclosure**: Coordinate a disclosure timeline with the reporter after a patch has been merged and deployed to production.

---

## Areas of Critical Focus

We particularly value reports related to:

- **Multi-Tenant Isolation**: Bypassing tenant boundaries in DynamoDB, S3, or Qdrant vector retrieval.
- **Cross-Role ACL Violations**: Retrieving or synthesizing answers from documents restricted by Cognito roles or user IDs.
- **Audit Hashchain Tampering**: Any flaw allowing modification, deletion, or forging of cryptographic audit chain records.
- **Data Leaks via Semantic Caching**: Extracting cross-tenant or cross-role data through cache collisions.
- **Prompt Injection & Guardrail Evasion**: System prompt escapes leading to unauthorized data exfiltration.
- **PII Leakage**: Circumvention of PII scrubbing engines resulting in raw PII persistence or generation.

---

## Safe Harbor

We consider security research conducted in good faith under this policy to be authorized. We will not pursue legal action against researchers who:
- Make a good faith effort to avoid privacy violations, data destruction, and service interruption.
- Give us reasonable time to remediate before public disclosure.
- Do not access, modify, or download user data beyond what is strictly necessary to demonstrate the vulnerability.
