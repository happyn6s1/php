# Login Page Security Advisory

This document provides a detailed security advisory for implementing a secure **login page** on a web application.

---

## 1. Authentication Mechanism

* Prefer **OpenID Connect (OIDC)** or **OAuth 2.0** login for SSO.
* If using password-based authentication:

  * Use **bcrypt, scrypt, or Argon2**.
  * Apply a **unique salt** per user.
  * Use an **adaptive cost factor** to resist brute-force attacks.

---

## 2. Password Policy

* Minimum length: 12+ characters.
* Encourage passphrases.
* Rate-limit login attempts (e.g., 5-10 per IP/account per hour).
* Offer **MFA** (TOTP, WebAuthn/FIDO2) for sensitive accounts.

---

## 3. Session Management

* Use **secure, HttpOnly, SameSite=strict cookies** for session tokens.
* Regenerate session tokens on login and privilege elevation.
* Set **idle and absolute session timeouts**.
* Protect against **session fixation attacks**.

---

## 4. Transport Security

* Enforce **HTTPS/TLS 1.2+**.
* Redirect HTTP to HTTPS.
* Use **HSTS headers**.
* Avoid sending sensitive data in URLs.

---

## 5. Input Validation & Injection Protection

* Validate login inputs server-side.
* Use **parameterized queries** to prevent SQL injection.
* Use generic error messages: "Invalid credentials".

---

## 6. Brute Force / Enumeration Protection

* Rate-limit login attempts per IP/account.
* Introduce **progressive delays** or **CAPTCHA** after multiple failures.
* Avoid revealing account existence through errors.

---

## 7. Account Recovery & Reset

* Time-limited, one-time-use reset tokens.
* Send only via verified email.
* Tokens should be cryptographically random.
* Avoid security questions.

---

## 8. Logging & Monitoring

* Log failed and successful login attempts (exclude passwords).
* Monitor for unusual patterns: multiple failures, abnormal locations.
* Alert admins for suspicious activity.

---

## 9. Front-End Considerations

* Avoid exposing sensitive error details.
* Use **Content Security Policy (CSP)** to prevent XSS.
* Use frameworks that auto-escape outputs.
* Use HTTPS-only cookies for sessions.

---

## 10. Advanced / Optional Measures

* Implement **WebAuthn/FIDO2** for passwordless login.
* Account lockout after multiple failed attempts.
* IP reputation checks.
* Conduct penetration testing on login flow.

---

## Security Checklist

| Area                 | Checklist                                               |
| -------------------- | ------------------------------------------------------- |
| Password storage     | bcrypt/scrypt/Argon2 + salt + adaptive cost             |
| Transport            | HTTPS + HSTS                                            |
| Input validation     | Server-side, parameterized queries                      |
| Session              | Secure, HttpOnly, SameSite cookies; regenerate on login |
| MFA                  | TOTP/WebAuthn recommended                               |
| Brute force          | Rate limiting + CAPTCHA                                 |
| Error messages       | Generic, don’t reveal username existence                |
| Logging & monitoring | Log attempts, monitor anomalies                         |
| Account recovery     | One-time, expiring reset tokens; no security questions  |
| Front-end            | CSP, no sensitive info in HTML/JS                       |

---

**Key Principle:** Apply **defense-in-depth**, combining secure authentication, session management, data protection, and monitoring to reduce the attack surface of the login page.
