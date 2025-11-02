# Common PHP Vulnerabilities (8 examples)

Nice — here are **8 common PHP vulnerabilities** with short **vulnerable examples** and **safe fixes** you can copy/paste and study. Each section shows: what it is, why it matters, a minimal vulnerable snippet, and a secure alternative + quick mitigation notes.

---

## 1) SQL Injection (SQLi)

**What / Impact:** Attacker injects SQL via user input — data leak, data modification, auth bypass.

**Vulnerable (DON’T do this):**

```php
// vulnerable.php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = $id";     // unsafe string concat
$res = mysqli_query($conn, $sql);
```

**Safe fix (prepared statements):**

```php
// safe.php
$id = $_GET['id'];
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$res = $stmt->get_result();
```

**Notes:** Always use prepared statements / parameterized queries. Validate types (ints, emails) and limit DB privileges.

---

## 2) Cross-Site Scripting (XSS)

**What / Impact:** Attacker injects JS/HTML that runs in other users’ browsers — session theft, defacement.

**Vulnerable:**

```php
// vulnerable.php
echo "Welcome, " . $_GET['name'];   // prints raw user input
```

**Safe fix (output-encoding):**

```php
// safe.php
echo "Welcome, " . htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

**Notes:** Encode on output for the correct context (HTML, attribute, JS, URL). Use a templating engine that auto-escapes when possible.

---

## 3) Cross-Site Request Forgery (CSRF)

**What / Impact:** Unauthorized state-changing request (like changing password) is performed by a victim without intent.

**Vulnerable (no token):**

```php
// change_email.php (vulnerable)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new = $_POST['email'];
    // update email without checking token
}
```

**Safe fix (CSRF token):**

```php
// form.php - generate
session_start();
if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
$token = $_SESSION['csrf'];
// include <input type="hidden" name="csrf" value="<?= htmlspecialchars($token) ?>">
```

```php
// change_email.php - verify
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
        http_response_code(400); exit('Bad CSRF token');
    }
    // safe to proceed
}
```

**Notes:** Use SameSite cookies, require POST for state changes, and regenerate tokens per session (or per form).

---

## 4) File Upload / Path Traversal

**What / Impact:** Upload can overwrite files or allow uploading executable code; path traversal lets attacker read/modify files.

**Vulnerable:**

```php
// vulnerable.php
move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/' . $_FILES['f']['name']);
```

**Safe fix:**

```php
// safe.php
$fname = bin2hex(random_bytes(16)) . '.' . pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION);
$allowed = ['jpg','png','pdf'];
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) { exit('bad file'); }
$dest = '/var/www/uploads/' . $fname;
if (!move_uploaded_file($_FILES['f']['tmp_name'], $dest)) { exit('fail'); }
// store $fname in DB
```

**Notes:** Store uploads outside webroot or deny execution via server config. Validate MIME type, extension, size. Use random names, and avoid trusting filenames from users.

---

## 5) Remote Code Execution via `eval()` or `create_function`

**What / Impact:** Executing attacker-controlled strings leads to complete remote code execution.

**Vulnerable:**

```php
// vulnerable.php
$code = $_GET['code'];
eval($code);   // extremely dangerous
```

**Safe fix:**

* **Avoid `eval()` entirely.** Use a whitelist of actions, callbacks, or safe interpreters.

```php
// safe.php - whitelist pattern
$action = $_GET['action'] ?? '';
$allowed = ['list','download'];
if (!in_array($action, $allowed, true)) exit('bad');
if ($action === 'list') { /* ... */ }
```

**Notes:** If you need templating, use a safe template engine. Never eval user input.

---

## 6) Insecure Deserialization (`unserialize`)

**What / Impact:** `unserialize()` on attacker input can reconstruct objects with magic methods that do dangerous things — RCE, privilege escalation.

**Vulnerable:**

```php
// vulnerable.php
$data = $_POST['payload'];
$obj = unserialize($data);  // unsafe on untrusted input
```

**Safe fix:**

```php
// safe.php
// Prefer JSON
$data = json_decode($_POST['payload'] ?? 'null', true);
if (json_last_error() !== JSON_ERROR_NONE) exit('invalid json');
```

Or if you must unserialize, use `allowed_classes` parameter (PHP 7+):

```php
$obj = unserialize($data, ["allowed_classes" => false]); // disallow classes
```

**Notes:** Avoid passing user-controlled serialized PHP objects. Prefer JSON, and validate all fields.

---

## 7) Session Fixation / Weak Session Management

**What / Impact:** Attacker forces a user to use a known session ID, then logs in and hijacks that session.

**Vulnerable pattern:**

* Not regenerating session ID after login.

**Safe fix:**

```php
// login.php (after successful auth)
session_regenerate_id(true); // rotate session id
$_SESSION['user_id'] = $userId;
```

**Notes:** Set secure cookie flags: `session.cookie_httponly`, `session.cookie_secure`, and `session.cookie_samesite`. Use short timeouts and revoke sessions on logout or password change.

---

## 8) Command Injection

**What / Impact:** Passing user input to shell commands allows executing arbitrary commands on the server.

**Vulnerable:**

```php
// vulnerable.php
$user = $_GET['file'];
echo shell_exec("cat " . $user);   // dangerous
```

**Safe fix:**

* Avoid shell when possible. If needed, use `escapeshellarg()` and strict validation:

```php
// safe.php
$file = $_GET['file'];
if (!preg_match('/^[a-z0-9_\-]+\.txt$/i', $file)) exit('invalid filename');
$cmd = 'cat ' . escapeshellarg('/safe/dir/' . $file);
echo shell_exec($cmd);
```

**Notes:** Prefer native PHP functions (`file_get_contents`) over shell. Run services with least privilege.

---

## Quick general mitigation checklist

* Use parameterized DB queries, input validation, and output encoding.
* Principle of least privilege (DB user, file system, processes).
* Keep PHP and libs updated; apply security patches.
* Use HTTPS everywhere; set secure cookie flags.
* Use `Content-Security-Policy` to mitigate some XSS.
* Centralize input validation and sanitize at the boundary.
* Employ security headers (CSP, X-Frame-Options, X-Content-Type-Options).
* Use static analysis / SAST tools and run web app scanners in dev/staging (not on third-party sites).
* Log suspicious activity and monitor for anomalies.

---

*File generated from a ChatGPT summary of common vulnerabilities. Modify as needed.*
