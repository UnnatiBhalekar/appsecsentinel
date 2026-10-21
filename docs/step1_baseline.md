# Step 1 — Scanner Accuracy Baseline

**Date:** 2026-10-21  
**Scanner:** `scan_owasp_vulnerabilities` in `server.py` (unmodified)  
**Test file:** `tests/test_scanner.py`  
**Evaluator:** `evaluate.py`

---

## Results

| Metric | Value |
|---|---|
| Total test cases | 39 |
| True Positives (TP) | 24 |
| False Positives (FP) | 2 |
| False Negatives (FN) | 1 |
| True Negatives (TN) | 12 |
| **Precision** | **92.3%** |
| **Recall** | **96.0%** |

**Precision** answers: *"Of everything the scanner flagged, how much was actually dangerous?"*  
**Recall** answers: *"Of all the genuinely dangerous snippets, how many did the scanner catch?"*

---

## Raw output from `python evaluate.py`

```
Running evaluation…
Total cases: 39

============================================================
SCANNER ACCURACY REPORT — AppSecSentinel v1 baseline
============================================================
Total test cases  : 39
True  Positives   : 24  (vulnerable snippets correctly flagged)
False Positives   : 2  (safe snippets wrongly flagged)
False Negatives   : 1  (vulnerable snippets missed)
True  Negatives   : 12  (safe snippets correctly cleared)
Precision         : 92.3%  (TP / (TP + FP))
Recall            : 96.0%  (TP / (TP + FN))

WRONG RESULTS (3):
------------------------------------------------------------
  [CLEAN]  sql_fstring_inline
    Expected : FLAGGED
    Scanner  : ✅ No OWASP Top 10 vulnerability patterns detected…

  [FLAGGED]  xss_inner_html_sanitized
    Expected : CLEAN
    Scanner  : ⚠️  OWASP VULNERABILITY SCAN REPORT (JAVASCRIPT) …

  [FLAGGED]  deser_yaml_load_with_safeloader
    Expected : CLEAN
    Scanner  : ⚠️  OWASP VULNERABILITY SCAN REPORT (PYTHON) …
```

---

## Explanation of every wrong result

### 1. `sql_fstring_inline` — False Negative (scanner missed a real vulnerability)

**Code tested:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**What happened:** The scanner returned "clean" even though this is genuinely dangerous SQL injection.

**Why the scanner missed it:**

The SQL injection regex looks for three things, in order, left to right:
1. A SQL keyword like `SELECT`
2. A keyword like `FROM` or `WHERE`
3. A string-building indicator — one of `+`, `${`, `%s`, `.format(`, or **`f"`**

In the snippet `f"SELECT * FROM users WHERE id = {user_id}"`, the `f"` prefix (which marks it as an f-string) appears at the very *start* of the line, *before* `SELECT`. The regex can only match things in order, so it finds `SELECT` first, then `FROM`, but then needs to find `f"` *after* `FROM` — and it can't, because `f"` already came before `SELECT`.

Think of it like a metal detector that only looks forward: it walked right past the `f"` before it even started searching for SQL keywords, so it never circled back.

**Real-world impact:** Python f-strings used to build SQL queries are among the most common injection patterns in modern Python code. This is an important gap.

---

### 2. `xss_inner_html_sanitized` — False Positive (scanner flagged safe code)

**Code tested:**
```javascript
element.innerHTML = DOMPurify.sanitize(userInput);
```

**What happened:** The scanner flagged this as an XSS vulnerability even though DOMPurify removes all dangerous HTML before assignment.

**Why the scanner flagged it:**

The XSS regex simply looks for the text `innerHTML =` anywhere in the code. It fires immediately — it does not look at what comes after the `=`. Whether you write:

```javascript
element.innerHTML = userInput;          // DANGEROUS
element.innerHTML = DOMPurify.sanitize(userInput); // SAFE
```

…the pattern `innerHTML\s*=` matches both. The scanner has no way to know that the right-hand side is sanitised.

This is a fundamental limitation of **pattern-based (regex) SAST**. Understanding the semantics of `DOMPurify.sanitize()` requires data-flow analysis — tracking where the value came from and what transformations happened to it — which is well beyond what a regex can do.

**Real-world impact:** This kind of false positive wastes developer time during code review. A developer running the scanner on a well-written codebase would have to manually dismiss this finding.

---

### 3. `deser_yaml_load_with_safeloader` — False Positive (scanner flagged safe code)

**Code tested:**
```python
config = yaml.load(file_content, Loader=yaml.SafeLoader)
```

**What happened:** The scanner flagged this as unsafe deserialisation even though `yaml.SafeLoader` makes this call safe.

**Why the scanner flagged it:**

The deserialisation regex tries to distinguish safe from unsafe `yaml.load` calls using a **negative lookahead**. The intent was: "flag `yaml.load(...)` *unless* `, Loader` appears right after the closing parenthesis."

```
yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)
```

The problem is where the lookahead is placed. `(?!\s*,\s*Loader)` checks what comes *after the closing `)` of the function call*. But `Loader=yaml.SafeLoader` is *inside* the parentheses, swallowed by `[^)]*`. So after the `)`, there is nothing — the lookahead condition "NOT followed by `, Loader`" is trivially true, and the match fires anyway.

It is like a smoke detector designed to ignore candles but positioned facing away from the candle — it still sees smoke.

To fix this properly, the pattern would need to check *inside* the argument list, for example by only matching `yaml.load(` followed by a single argument (no comma): `yaml\.load\s*\(\s*[^,)]+\s*\)`.

**Real-world impact:** `yaml.load` with `Loader=yaml.SafeLoader` is the recommended upgrade path from the unsafe default. Flagging it as dangerous could discourage developers from using the safer form.

---

## Test case coverage

| Category | Vulnerable cases | Safe look-alikes |
|---|---|---|
| SQL Injection | 4 (concat, %, .format, f-string) | 2 |
| Command Injection | 3 (os.system, shell=True, Java exec) | 1 |
| XSS | 4 (innerHTML, document.write, eval, setTimeout) | 2 |
| Weak Hashing | 3 (MD5 Python, MD5 Java, SHA-1) | 1 |
| Insecure Ciphers | 2 (DES, AES/ECB) | 1 |
| Insecure Deserialisation | 2 (pickle, yaml.load) | 3 |
| Path Traversal | 2 (Python concat, Java backslash) | 1 |
| XXE | 1 | 1 |
| Hardcoded Secrets | 3 (AWS key, password, private key) | 1 |
| Insecure Randomness | 1 (Math.random) | 1 |

---

## What to fix in Step 2

1. **sql_fstring_inline (FN):** Extend the SQL injection regex to also catch Python f-strings where the `f"` comes before the SQL keyword. A new pattern like `f['\"].*?(SELECT|INSERT|UPDATE|DELETE).*?{` would cover this.
2. **xss_inner_html_sanitized (FP):** Add a negative lookahead after `innerHTML\s*=` to skip matches where the RHS calls a known sanitiser (DOMPurify.sanitize, sanitizeHtml, etc.).
3. **deser_yaml_load_with_safeloader (FP):** Fix the negative lookahead position — check inside the argument list for a `Loader=` argument rather than after the closing paren.
