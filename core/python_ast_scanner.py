"""
core/python_ast_scanner.py
--------------------------
AST-based security scanner for Python source code.

Why AST and not regex?
  A regex sees a flat sequence of characters and has no memory between lines.
  The AST represents what the code *means*, so we can follow a value from
  where it is assigned  ("sql = 'SELECT...' + user_id")
  to where it is used   ("cursor.execute(sql)")
  — including across multiple lines or through intermediate variables.

If the code cannot be parsed as Python, this module returns an empty list
and the caller falls back to regex-based scanning.

Line numbers come directly from the AST node's .lineno attribute, which
Python's parser fills in for every expression node.
"""

import ast
from .models import Finding


# ─── Taint analysis ───────────────────────────────────────────────────────────

def _is_tainted(node: ast.expr | None, var_map: dict) -> bool:
    """
    Return True if `node` may carry non-constant (user-supplied) data.

    Constant       → never tainted (a string literal cannot be injected)
    Name           → look it up in var_map; if unknown, assume tainted
    JoinedStr      → tainted when any {} slot is a non-constant FormattedValue
    BinOp +        → tainted if either side is tainted (string concatenation)
    BinOp % str    → tainted when left side is a str constant ("...%s" % val)
    Call .format() → always tainted (we assume arguments carry user input)
    anything else  → not tainted by default (conservative: avoid false positives)
    """
    if node is None:
        return False

    if isinstance(node, ast.Constant):
        return False  # literals can never hold injected values

    if isinstance(node, ast.Name):
        resolved = var_map.get(node.id)
        if resolved is not None:
            return _is_tainted(resolved, var_map)
        return True  # unknown variable — function parameter or external, assume tainted

    if isinstance(node, ast.JoinedStr):  # f-string
        return any(isinstance(v, ast.FormattedValue) for v in node.values)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_tainted(node.left, var_map) or _is_tainted(node.right, var_map)

    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)):
        return True  # "template %s" % value

    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return True  # "...{}".format(x)

    return False


# ─── Per-call detectors ───────────────────────────────────────────────────────

_SQL_METHODS = {"execute", "executemany", "executescript"}


def _check_sql(call: ast.Call, var_map: dict) -> Finding | None:
    """
    Flag cursor.execute / executemany / executescript when the query argument
    is tainted.  Parameterised calls like execute(sql, (x,)) are safe as long
    as sql itself is a constant.
    """
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in _SQL_METHODS):
        return None
    if not call.args:
        return None
    if _is_tainted(call.args[0], var_map):
        return Finding(
            rule_id="SQL-002",
            severity="CRITICAL",
            owasp_category="A03 Injection",
            message=f"SQL Injection — tainted query in .{func.attr}() call",
            line_number=getattr(call, "lineno", 0),
        )
    return None


def _check_cmd(call: ast.Call, var_map: dict) -> Finding | None:
    """
    Flag os.system with a non-constant argument, and subprocess calls that
    use shell=True with a non-constant command string.
    """
    func = call.func

    # os.system(<non-constant>)
    if (isinstance(func, ast.Attribute) and func.attr == "system"
            and isinstance(func.value, ast.Name) and func.value.id == "os"):
        if call.args and _is_tainted(call.args[0], var_map):
            return Finding(
                rule_id="CMD-002",
                severity="CRITICAL",
                owasp_category="A03 Injection",
                message="Command Injection — os.system with non-constant argument",
                line_number=getattr(call, "lineno", 0),
            )

    # subprocess.call/run/Popen(cmd, shell=True) with a non-constant cmd
    if isinstance(func, ast.Attribute) and func.attr in {"call", "run", "Popen"}:
        shell_true = any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in call.keywords
        )
        if shell_true and call.args and _is_tainted(call.args[0], var_map):
            return Finding(
                rule_id="CMD-003",
                severity="CRITICAL",
                owasp_category="A03 Injection",
                message="Command Injection — subprocess with shell=True and non-constant command",
                line_number=getattr(call, "lineno", 0),
            )

    return None


def _check_deser(call: ast.Call, _var_map: dict) -> Finding | None:
    """
    Flag pickle.load/loads (no safe variant exists) and yaml.load called
    without an explicit Loader= keyword.
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    if (isinstance(func.value, ast.Name) and func.value.id == "pickle"
            and func.attr in {"load", "loads"}):
        return Finding(
            rule_id="DESER-002",
            severity="CRITICAL",
            owasp_category="A08 Insecure Deserialisation",
            message=f"Unsafe deserialisation — pickle.{func.attr}()",
            line_number=getattr(call, "lineno", 0),
        )

    if (isinstance(func.value, ast.Name) and func.value.id == "yaml"
            and func.attr == "load"):
        has_loader = any(kw.arg == "Loader" for kw in call.keywords)
        if not has_loader:
            return Finding(
                rule_id="DESER-003",
                severity="CRITICAL",
                owasp_category="A08 Insecure Deserialisation",
                message="Unsafe deserialisation — yaml.load without Loader argument",
                line_number=getattr(call, "lineno", 0),
            )

    return None


def _check_hash(call: ast.Call) -> Finding | None:
    """Flag hashlib.md5 and hashlib.sha1 — cryptographically broken."""
    func = call.func
    if (isinstance(func, ast.Attribute)
            and func.attr in {"md5", "sha1"}
            and isinstance(func.value, ast.Name)
            and func.value.id == "hashlib"):
        return Finding(
            rule_id="HASH-002" if func.attr == "md5" else "HASH-003",
            severity="HIGH",
            owasp_category="A02 Cryptographic Failures",
            message=f"Weak hashing algorithm — hashlib.{func.attr}()",
            line_number=getattr(call, "lineno", 0),
        )
    return None


# ─── Variable map builder ─────────────────────────────────────────────────────

def _build_var_map(stmts: list[ast.stmt]) -> dict:
    """
    Walk a list of statements and record the last simple-name assignment
    for each variable.  Flat single-scope: good enough for same-function
    variable indirection.
    """
    var_map: dict[str, ast.expr] = {}
    for node in ast.walk(ast.Module(body=list(stmts), type_ignores=[])):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_map[target.id] = node.value
    return var_map


# ─── Public entry point ───────────────────────────────────────────────────────

def scan_python(code: str) -> list[Finding]:
    """
    Parse `code` as Python and return security findings.
    Returns [] (not an error) on SyntaxError — caller uses regex as fallback.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()  # (rule_id, lineno) — avoid duplicates

    def _add(f: Finding | None) -> None:
        if f and (f.rule_id, f.line_number) not in seen:
            findings.append(f)
            seen.add((f.rule_id, f.line_number))

    # ── Per-function scan (local var_map for variable indirection) ──────────
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            var_map = _build_var_map(node.body)
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    _add(_check_sql(inner, var_map))
                    _add(_check_cmd(inner, var_map))
                    _add(_check_deser(inner, var_map))
                    _add(_check_hash(inner))

    # ── Module-level scan (top-level statements only, skip function bodies) ─
    # Build module var_map from direct Assign nodes in tree.body
    module_var_map: dict[str, ast.expr] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    module_var_map[t.id] = stmt.value

    # Walk each top-level statement that is not a function/class definition
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # already handled per-function above
        for inner in ast.walk(stmt):
            if isinstance(inner, ast.Call):
                _add(_check_sql(inner, module_var_map))
                _add(_check_cmd(inner, module_var_map))
                _add(_check_deser(inner, module_var_map))
                _add(_check_hash(inner))

    return findings
