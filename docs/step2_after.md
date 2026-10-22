# Step 2 — After AST Fix

**Date:** 2026-10-21  
**Scanner:** `scan_owasp_vulnerabilities` in `server.py` (AST + regex)  
**Test file:** 39 easy + 15 hard = 54 total cases

---

## Before vs After

| Metric | Before (regex only) | After (AST + regex) | Change |
|---|---|---|---|
| **EASY Precision** | 92.3% | 100.0% | +7.7 pp |
| **EASY Recall** | 96.0% | 96.0% | — |
| **HARD Precision** | 66.7% | 100.0% | +33.3 pp |
| **HARD Recall** | 57.1% | 100.0% | +42.9 pp |
| **Combined Precision** | 87.5% | 100.0% | +12.5 pp |
| **Combined Recall** | 87.5% | 96.9% | +9.4 pp |

---

## Detailed results

### EASY group (39 cases)

Wrong: 1 (down from 3)

- `sql_fstring_inline` — **FN still present** (see explanation below)
- ~~`xss_inner_html_sanitized`~~ — fixed (DOMPurify negative lookahead in regex)
- ~~`deser_yaml_load_with_safeloader`~~ — fixed (both regex and AST now handle SafeLoader correctly)

### HARD group (15 cases)

Wrong: 0 (down from 5)

All three false negatives fixed by the AST scanner:
- ~~`hard_sql_split_lines`~~ — AST resolves `sql` variable to its BinOp(Add) value
- ~~`hard_sql_chain_variable`~~ — AST recursively resolves chained variables
- ~~`hard_cmd_multiline_shell_variable`~~ — AST reads multi-line call as one `Call` node

Both false positives eliminated:
- ~~`hard_yaml_safeloader`~~ — AST checks for `Loader=` keyword; fixed regex also helps
- ~~`hard_xss_dompur`~~ — DOMPurify lookahead in XSS regex

---

## What the AST can see that a regex cannot

### 1. Variable indirection

```python
# Regex only sees two separate lines — it can't link them
sql = "SELECT * FROM users WHERE id = " + user_id   # line 1
cursor.execute(sql)                                   # line 2
```

The AST represents this as two nodes in memory. `_build_var_map` records
`sql → BinOp(Add, Constant, Name("user_id"))`. When `_check_sql` inspects the
`execute` call's first argument, it calls `_is_tainted(Name("sql"), var_map)`,
which resolves to the BinOp and returns `True`.

### 2. Multi-line calls

```python
result = subprocess.run(
    cmd,           # line 2
    shell=True,    # line 3
)
```

Without `re.DOTALL`, the regex's `.*` cannot cross the newline between `run(`
and `shell=True`. The AST has no concept of lines — `subprocess.run(...)` is
a single `ast.Call` node with `cmd` in `.args` and `shell=True` in
`.keywords`, regardless of how it was formatted.

### 3. Context-aware deserialization

```python
yaml.load(stream)                      # unsafe — no Loader
yaml.load(stream, Loader=yaml.SafeLoader)  # safe — Loader specified
```

The AST reads `.keywords` on the call node and checks for `Loader=`. The old
regex checked for `, Loader` in the text *after* the closing `)`, where it
never appeared because the argument is *inside* the parens.

---

## What is still missed

### `sql_fstring_inline` (remaining FN)

```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

This snippet has no `cursor.execute()` call — it is only the string assignment.
The AST scanner fires at the point of *use* (the execute call), not the point
of *construction*. If the calling code is not in the same snippet, the scanner
cannot see it.

**Root cause:** The test case represents a fragment, not a complete function.
In a real codebase this string would appear in a function alongside its
`cursor.execute(query)` call, which the AST scanner would catch correctly
(see `hard_sql_chain_variable` — a structurally identical pattern that the
scanner does catch).

**Resolution options:**
- Flag any f-string used in a SQL-keyword-containing assignment (adds FPs on
  legitimate templating), or
- Accept this as a known limitation of fragment-based testing and document it.

---

## Changes made in server.py

| # | What | Why |
|---|---|---|
| 1 | Import `scan_python` from `core.python_ast_scanner` | Wire in the new scanner |
| 2 | Run AST scan before regex; skip regex for categories AST covered | Avoid duplicate findings; give AST priority where it has better accuracy |
| 3 | XSS regex: add `(?!\s*DOMPurify\.sanitize\s*\()` lookahead | Skip sanitised innerHTML assignments |
| 4 | yaml regex: `[^)]*\)(?!\s*,\s*Loader)` → `\(\s*[^,)]+\s*\)` | Match only single-arg form; stop at first comma so `Loader=` is excluded |
| 5 | XSS category: `A03 Injection / A07 XSS` → `A03 Injection` | XSS is an injection category per OWASP Top 10 2021 |
| 6 | Randomness category: `A09 Security Logging Failures` → `A02 Cryptographic Failures` | Weak entropy for tokens is a cryptographic failure, not a logging failure |
