# Web Application Hardening Checklist

This document provides a structured guide for **hardening a web application** to reduce attack surface and prevent common vulnerabilities.

---

## 1. Input Validation & Output Encoding

* Sanitize all user inputs using whitelists.
* Use prepared statements and parameterized queries to prevent SQL/NoSQL injection.
* Properly encode outputs for HTML, JavaScript, CSS, and URLs to prevent XSS.
* Validate file uploads for MIME type, size, and malware.

---

## 2. Authentication & Session Management

* Implement strong authentication: OAuth2.0 / OpenID Connect, MFA.
* Store passwords securely with bcrypt/argon2 and strong salts.
* Secure session cookies with `HttpOnly`, `Secure`, and `SameSite` attributes.
* Rotate session IDs on login and privilege changes.
* Limit login attempts to mitigate brute-force attacks.

---

## 3. Access Control

* Implement proper authorization on every request, not just in the UI.
* Enforce Principle of Least Privilege (PoLP) for users, APIs, and services.
* Use Role-Based or Attribute-Based Access Control (RBAC/ABAC).

---

## 4. Data Protection

* Encrypt sensitive data at rest (AES-256 or equivalent).
* Encrypt data in transit using HTTPS/TLS 1.2+.
* Secure cookies and tokens; sign/encrypt JWTs.
* Store secrets securely in vaults or environment variables.

---

## 5. Application & Server Configuration

* Harden web server: disable unnecessary modules, directory listings, and verbose errors.
* Remove default credentials, sample pages, and admin endpoints.
* Use Content Security Policy (CSP) to mitigate XSS.
* Set secure headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`.

---

## 6. API Security

* Apply rate limiting and throttling to prevent DoS.
* Validate API inputs using schema validation (OpenAPI/JSON Schema).
* Verify JWT signatures, expiration, and claims.
* Limit exposure of unnecessary endpoints.

---

## 7. Dependency & Supply Chain Security

* Use vetted libraries and track dependencies.
* Monitor for vulnerabilities with Snyk, Dependabot, or npm audit.
* Use Subresource Integrity (SRI) for third-party scripts.

---

## 8. Logging & Monitoring

* Centralize logs including auth attempts, errors, and suspicious activity.
* Mask sensitive data (passwords, tokens, PII).
* Set up alerts for unusual login patterns, brute-force attempts, or abnormal API usage.

---

## 9. Backup & Recovery

* Maintain regular encrypted backups offsite.
* Test restore procedures to ensure quick recovery.

---

## 10. Development & Testing Practices

* Follow secure coding standards (OWASP Top 10).
* Use static and dynamic testing (SAST/DAST).
* Conduct regular penetration tests.
* Perform threat modeling for new features or architecture changes.

---

## Summary Table

| Area             | Hardening Measures                                  |
| ---------------- | --------------------------------------------------- |
| Input Validation | Whitelists, sanitize inputs, encode outputs         |
| Authentication   | MFA, OAuth2/OIDC, strong passwords                  |
| Access Control   | RBAC/ABAC, least privilege                          |
| Data Protection  | TLS, AES encryption, secure storage                 |
| Server Config    | Harden web server, secure headers, CSP              |
| API Security     | Rate limiting, JWT validation, schema checks        |
| Dependencies     | Track, patch, use vetted libraries                  |
| Monitoring       | Centralized logs, alerts, mask sensitive info       |
| Backup           | Encrypted, offsite, tested                          |
| Development      | Secure coding, SAST/DAST, pentests, threat modeling |

---

**Key Principle:** Defense-in-depth. Combine secure coding, authentication, data encryption, monitoring, and hardened infrastructure to reduce attack surface.
