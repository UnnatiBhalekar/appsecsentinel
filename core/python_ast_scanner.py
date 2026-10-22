"""
python_ast_scanner.py
---------------------
AST-based security scanner for Python code.

Why AST instead of regex?
  A regex sees a flat sequence of characters and has no memory between lines.
  An AST is a tree that represents what the code *means* — so we can follow a
  value from where it is created ("sql = 'SELECT...' + user_id") to where it
  is used ("cursor.execute(sql)") without ever reading raw text.

Checks implemented:
  - SQL injection in execute / executemany / executescript calls
  - Command injection via subprocess (shell=True) and os.system
  - Unsafe deserialisation via pickle.load/loads and yaml.load without Loader
  - Weak hashing via hashlib.md5 and hashlib.sha1

If the code cannot be parsed as Python (SyntaxError), the caller should fall
back to regex scanning.
"""

import ast
from typing import NamedTuple


class Finding(NamedTuple):
    severity: str
    category: str
    label: str


# ─── Taint helpers ────────────────────────────────────────────────────────────

def _is_tainted(node: ast.expr | None, var_map: dict) -> bool:
    """
    Return True if `node` may contain non-constant (user-supplied) data.

    Rules:
      Constant          → safe  (a string literal never carries user input)
      Name              → look it up in var_map; if unknown, assume tainted
      JoinedStr (f"..") → tainted if it contains any FormattedValue ({expr})
      BinOp +           → tainted if either side is tainted
      BinOp % (str fmt) → tainted when the left side is a string constant (%s)
      Call .format()    → always tainted (we assume arguments are user-supplied)
      anything else     → not tainted by default (conservative: avoid FPs)
    """
    if node is None:
        return False

    # Pure constant — a string literal can never be injection
    if isinstance(node, ast.Constant):
        return False

    # Variable reference — resolve through assignment map
    if isinstance(node, ast.Name):
        resolved = var_map.get(node.id)
        if resolved is not None:
            return _is_tainted(resolved, var_map)
        # Unknown variable (e.g. a function parameter) — assume tainted
        return True

    # f-string: tainted if any {} slot contains a non-constant expression
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)

    # String concatenation: tainted if either operand is tainted
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_tainted(node.left, var_map) or _is_tainted(node.right, var_map)

    # "template %s" % value — tainted when left side is a string
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)):
        return True

    # str.format() call — treat any call to .format() as tainted
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return True

    return False  # conservative default: don't flag unknown node types


# ─── Per-call checkers ────────────────────────────────────────────────────────

_SQL_METHODS = {"execute", "executemany", "executescript"}


def _check_sql(call: ast.Call, var_map: dict) -> Finding | None:
    """
    Flag cursor.execute / executemany / executescript when the first argument
    (the query string) is tainted — i.e. built from non-constant parts.
    Parameterised queries like execute(sql, (user_id,)) are safe when sql itself
    is a Constant.
    """
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr in _SQL_METHODS):
        return None
    if not call.args:
        return None
    if _is_tainted(call.args[0], var_map):
        return Finding(
            "CRITICAL",
            "A03 Injection",
            f"SQL Injection — tainted first argument to .{func.attr}() (AST)",
        )
    return None


def _check_cmd(call: ast.Call, var_map: dict) -> Finding | None:
    """
    Flag os.system(expr) with a non-constant argument, and subprocess calls
    that pass shell=True with a non-constant command.
    """
    func = call.func

    # os.system(<non-constant>)
    if (isinstance(func, ast.Attribute) and func.attr == "system"
            and isinstance(func.value, ast.Name) and func.value.id == "os"):
        if call.args and _is_tainted(call.args[0], var_map):
            return Finding(
                "CRITICAL",
                "A03 Injection",
                "Command Injection — os.system with non-constant argument (AST)",
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
                "CRITICAL",
                "A03 Injection",
                "Command Injection — subprocess with shell=True and non-constant command (AST)",
            )

    return None


def _check_deser(call: ast.Call, var_map: dict) -> Finding | None:
    """
    Flag pickle.load/loads (always unsafe), and yaml.load called without any
    Loader keyword argument.  When Loader= is present the caller chose a loader
    explicitly, so we do not flag it (even if UnsafeLoader is used — that is a
    separate concern beyond this scanner's scope).
    """
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    # pickle.load or pickle.loads — no safe variant exists
    if (isinstance(func.value, ast.Name) and func.value.id == "pickle"
            and func.attr in {"load", "loads"}):
        return Finding(
            "CRITICAL",
            "A08 Insecure Deserialisation",
            f"Unsafe deserialisation — pickle.{func.attr}() (AST)",
        )

    # yaml.load without Loader= keyword
    if (isinstance(func.value, ast.Name) and func.value.id == "yaml"
            and func.attr == "load"):
        has_loader = any(kw.arg == "Loader" for kw in call.keywords)
        if not has_loader:
            return Finding(
                "CRITICAL",
                "A08 Insecure Deserialisation",
                "Unsafe deserialisation — yaml.load without Loader argument (AST)",
            )

    return None


def _check_hash(call: ast.Call) -> Finding | None:
    """
    Flag hashlib.md5 and hashlib.sha1 — both are cryptographically broken for
    password hashing or digital signatures.
    """
    func = call.func
    if (isinstance(func, ast.Attribute)
            and func.attr in {"md5", "sha1"}
            and isinstance(func.value, ast.Name)
            and func.value.id == "hashlib"):
        return Finding(
            "HIGH",
            "A02 Cryptographic Failures",
            f"Weak hashing algorithm — hashlib.{func.attr}() (AST)",
        )
    return None


# ─── Variable map builder ─────────────────────────────────────────────────────

def _build_var_map(scope_nodes) -> dict:
    """
    Walk a sequence of AST nodes and collect the last simple-name assignment
    for each variable.  This is a flat, single-scope approximation — good
    enough to catch variable-indirection patterns in the same function or
    module body.
    """
    var_map: dict[str, ast.expr] = {}
    for node in ast.walk(ast.Module(body=list(scope_nodes), type_ignores=[])):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_map[target.id] = node.value
    return var_map


# ─── Public entry point ───────────────────────────────────────────────────────

def scan_python(code: str) -> list[Finding]:
    """
    Parse `code` as Python and return a list of security findings.
    Returns an empty list (NOT an error) if the code has a SyntaxError —
    the caller should fall back to regex scanning in that case.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []  # not Python — signal caller to use regex

    findings: list[Finding] = []
    seen_labels: set[str] = set()  # deduplicate identical labels

    def _add(f: Finding | None) -> None:
        if f and f.label not in seen_labels:
            findings.append(f)
            seen_labels.add(f.label)

    # Scan each function/async-function with its own local variable map
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            var_map = _build_var_map(node.body)
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    _add(_check_sql(inner, var_map))
                    _add(_check_cmd(inner, var_map))
                    _add(_check_deser(inner, var_map))
                    _add(_check_hash(inner))

    # Also scan module-level statements (code not inside any function)
    module_var_map = _build_var_map(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _add(_check_sql(node, module_var_map))
            _add(_check_cmd(node, module_var_map))
            _add(_check_deser(node, module_var_map))
            _add(_check_hash(node))

    return findings
