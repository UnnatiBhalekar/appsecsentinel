# Step 2 — Before AST Fix

**Date:** 2026-10-21  
**Scanner:** `scan_owasp_vulnerabilities` in `server.py` (regex-only, unmodified)  
**Test file:** 39 easy + 15 hard = 54 total cases

---

## Results

### EASY group (original 39 cases)

| Metric | Value |
|---|---|
| True Positives | 24 |
| False Positives | 2 |
| False Negatives | 1 |
| True Negatives | 12 |
| **Precision** | **92.3%** |
| **Recall** | **96.0%** |

Wrong (same as Step 1 baseline):
- `sql_fstring_inline` — FN (f-string prefix before SQL keywords)
- `xss_inner_html_sanitized` — FP (regex matches innerHTML= regardless of sanitiser)
- `deser_yaml_load_with_safeloader` — FP (negative lookahead checks after `)`, not inside)

---

### HARD group (new 15 cases)

| Metric | Value |
|---|---|
| True Positives | 4 |
| False Positives | 2 |
| False Negatives | 3 |
| True Negatives | 6 |
| **Precision** | **66.7%** |
| **Recall** | **57.1%** |

Wrong (5 cases):
- `hard_sql_split_lines` — FN: query built in a variable, executed on the next line
- `hard_sql_chain_variable` — FN: taint flows through two intermediate variables
- `hard_cmd_multiline_shell_variable` — FN: subprocess.run call spans multiple lines; the regex's `.*` doesn't cross newlines
- `hard_yaml_safeloader` — FP: misplaced negative lookahead flags `yaml.load(..., Loader=yaml.SafeLoader)`
- `hard_xss_dompur` — FP: `innerHTML = DOMPurify.sanitize(...)` flagged despite sanitisation

Hard cases the regex DID catch (TP):
- `hard_sql_multiline_fstrings` — caught because a subsequent `f"` token appears after `FROM` in the text
- `hard_sql_format_execute` — `.format(` appears after SQL keywords
- `hard_sql_percent_execute` — `%s` appears after SQL keywords
- `hard_yaml_no_loader` — `yaml.load(` without comma → regex fires correctly

---

### Combined (54 cases)

| Metric | Value |
|---|---|
| True Positives | 28 |
| False Positives | 4 |
| False Negatives | 4 |
| True Negatives | 18 |
| **Precision** | **87.5%** |
| **Recall** | **87.5%** |

---

## Why the hard cases exposed the regex limits

A regex applies to raw text. It has no concept of "this string is used later as a database query" — it only sees characters. Three distinct failure modes appeared:

1. **Cross-line blindness:** The command injection pattern has no DOTALL flag. A `subprocess.run(` call spanning three lines is invisible to it.
2. **Variable indirection:** The SQL injection pattern requires both SQL keywords AND a string-building indicator within one regex match. When the indicator is on line 1 and the `cursor.execute()` is on line 2, the regex cannot link them.
3. **Context-free matching:** `innerHTML =` always matches, whether or not the value is sanitised. The regex cannot evaluate the semantics of the right-hand side.
