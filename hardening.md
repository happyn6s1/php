# System Hardening Checklist

This document provides a structured guide for **hardening a system against attacks**, covering multiple layers of defense.

---

## 1. Operating System Hardening

* Keep OS and kernel patched; automate security updates.
* Disable unnecessary services, daemons, and open ports.
* Remove default accounts; enforce least privilege; use sudo instead of root.
* Enable full-disk encryption; mount sensitive directories with `noexec`, `nodev`, `nosuid`.
* Centralize system logs for auditing.
* Use security frameworks like SELinux or AppArmor.
* Conduct periodic audits using CIS benchmarks or Lynis.

---

## 2. Network Hardening

* Restrict inbound/outbound traffic with firewalls.
* Segment networks (frontend, app, database); isolate management networks.
* Enforce TLS 1.2+ with strong ciphers; use HSTS and certificate pinning.
* Require VPN or identity-aware proxy for admin access.
* Apply DDoS protection: rate limiting, WAF, CDN filtering.

---

## 3. Application Hardening

* Validate and sanitize all user input; prevent SQLi, XSS, and injection attacks.
* Use OAuth 2.0 / OpenID Connect for authentication; store passwords securely (bcrypt, argon2).
* Manage secrets securely: avoid hardcoding; use Vault or environment variables.
* Secure session handling: `HttpOnly`, `SameSite`, `Secure` cookies; rotate tokens on privilege changes.
* Scan dependencies regularly; avoid unmaintained libraries.
* Enforce API security: rate limiting, schema validation, JWT verification.
* Hide detailed error messages and stack traces from users.

---

## 4. Identity & Access Hardening

* Apply the Principle of Least Privilege (PoLP) for users, APIs, and DBs.
* Require multi-factor authentication (MFA) for all accounts.
* Implement role-based or attribute-based access controls (RBAC / ABAC).
* Rotate credentials and keys regularly.
* Maintain audit trails and monitor for privilege escalation.

---

## 5. Monitoring, Detection, and Maintenance

* Centralize logs into SIEM systems (Splunk, ELK, CloudWatch).
* Deploy intrusion detection/prevention systems (OSSEC, Wazuh, Falco).
* Monitor file integrity with tools like Tripwire.
* Maintain encrypted, off-site backups; perform regular restore drills.
* Have an incident response plan with defined containment, eradication, and recovery steps.
* Conduct regular penetration tests.

---

## 6. DevOps & Cloud Considerations

* Use Infrastructure as Code (IaC) with security scanning tools (Checkov, tfsec).
* Use minimal, signed container images with read-only file systems.
* Enforce Kubernetes security policies (PodSecurityPolicies, network policies, restricted privileges).
* Apply least-privilege IAM policies; monitor cloud accounts with tools like CloudTrail or GuardDuty.

---

## 7. Layered Defense Summary

| Layer       | Goal                         | Typical Tools                   |
| ----------- | ---------------------------- | ------------------------------- |
| OS          | Reduce local attack surface  | CIS Benchmarks, SELinux         |
| Network     | Block unwanted access        | Firewalls, iptables, WAF        |
| Application | Prevent input-based exploits | OWASP ASVS, dependency scanners |
| Identity    | Control user access          | MFA, RBAC                       |
| Monitoring  | Detect & respond             | SIEM, IDS/IPS                   |

---

## 8. Final Tips

* Assume breach; design for containment.
* Encrypt data in transit and at rest.
* Continuously patch, monitor, and test; hardening is ongoing.
* Document baseline configuration according to CIS, NIST, or ISO 27001 guidance.
