"""
test_scanner.py
---------------
Measures the accuracy of scan_owasp_vulnerabilities() in server.py.

Each test case is:  (name, code_snippet, language, should_flag)
  - should_flag=True  => we expect the scanner to find at least one finding
  - should_flag=False => we expect a clean "no vulnerabilities" result

We cover every detection category with both a vulnerable example AND a
safe look-alike so we can see both false negatives and false positives.
"""

import sys
import os

# Allow importing from the project root without installing as a package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import scan_owasp_vulnerabilities

# ---------------------------------------------------------------------------
# Test cases: (name, code, language, should_flag)
# ---------------------------------------------------------------------------
CASES = [

    # ── SQL INJECTION ──────────────────────────────────────────────────────
    # String concatenation — the classic dangerous pattern
    ("sql_concat_python",
     'query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"',
     "python", True),

    # % format string — also dangerous
    ("sql_percent_format",
     'query = "SELECT * FROM users WHERE name = \'%s\'" % name',
     "python", True),

    # .format() call — dangerous
    ("sql_dot_format",
     'query = "SELECT * FROM users WHERE id = {}".format(user_id)',
     "python", True),

    # Parameterised query — SAFE (the right way)
    ("sql_parameterised_safe",
     'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
     "python", False),

    # Hard-coded SQL with no user input at all — SAFE
    ("sql_static_safe",
     'results = db.query("SELECT id, name FROM products WHERE active = 1")',
     "python", False),

    # f-string with SQL — DANGEROUS but regex likely misses it (FN expected)
    ("sql_fstring_inline",
     'query = f"SELECT * FROM users WHERE id = {user_id}"',
     "python", True),

    # ── COMMAND INJECTION ──────────────────────────────────────────────────
    # os.system — DANGEROUS
    ("cmd_os_system",
     'os.system("ls " + user_input)',
     "python", True),

    # subprocess shell=True — DANGEROUS
    ("cmd_subprocess_shell_true",
     'subprocess.call("generate_report.sh " + filename, shell=True)',
     "python", True),

    # subprocess with list (no shell) — SAFE
    ("cmd_subprocess_list_safe",
     'subprocess.run(["ls", filename], shell=False, check=True)',
     "python", False),

    # Java Runtime.exec — DANGEROUS
    ("cmd_java_runtime_exec",
     'Runtime.getRuntime().exec("cmd /c " + userInput)',
     "java", True),

    # ── CROSS-SITE SCRIPTING (XSS) ────────────────────────────────────────
    # innerHTML assignment — DANGEROUS
    ("xss_inner_html",
     'document.getElementById("out").innerHTML = userInput;',
     "javascript", True),

    # document.write — DANGEROUS
    ("xss_document_write",
     'document.write("<p>" + userText + "</p>");',
     "javascript", True),

    # eval() — DANGEROUS
    ("xss_eval",
     'eval(userCode);',
     "javascript", True),

    # setTimeout with string — DANGEROUS
    ("xss_settimeout_string",
     'setTimeout("alert(\'" + msg + "\')", 100);',
     "javascript", True),

    # textContent — SAFE alternative to innerHTML
    ("xss_text_content_safe",
     'document.getElementById("out").textContent = userInput;',
     "javascript", False),

    # innerHTML with sanitiser — SAFE in practice, but regex can't tell (FP expected)
    ("xss_inner_html_sanitized",
     'element.innerHTML = DOMPurify.sanitize(userInput);',
     "javascript", False),

    # ── WEAK HASHING ──────────────────────────────────────────────────────
    # MD5 in Python — WEAK
    ("hash_md5_python",
     'digest = hashlib.md5(password.encode()).hexdigest()',
     "python", True),

    # MD5 in Java — WEAK
    ("hash_md5_java",
     'MessageDigest md = MessageDigest.getInstance("MD5");',
     "java", True),

    # SHA-1 in Python — WEAK
    ("hash_sha1_python",
     'digest = hashlib.sha1(data.encode()).hexdigest()',
     "python", True),

    # SHA-256 — SAFE
    ("hash_sha256_safe",
     'digest = hashlib.sha256(password.encode()).hexdigest()',
     "python", False),

    # ── INSECURE CIPHERS ──────────────────────────────────────────────────
    # DES — WEAK
    ("cipher_des_java",
     'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
     "java", True),

    # AES/ECB — WEAK (ECB mode leaks patterns)
    ("cipher_aes_ecb",
     'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");',
     "java", True),

    # AES/GCM — SAFE (authenticated encryption)
    ("cipher_aes_gcm_safe",
     'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");',
     "java", False),

    # ── INSECURE DESERIALISATION ──────────────────────────────────────────
    # pickle.loads — DANGEROUS
    ("deser_pickle_loads",
     'obj = pickle.loads(request.body)',
     "python", True),

    # yaml.load without Loader — DANGEROUS
    ("deser_yaml_load_unsafe",
     'config = yaml.load(file_content)',
     "python", True),

    # yaml.load WITH SafeLoader — SAFE in practice, but regex may still flag it (FP expected)
    ("deser_yaml_load_with_safeloader",
     'config = yaml.load(file_content, Loader=yaml.SafeLoader)',
     "python", False),

    # yaml.safe_load — SAFE (the correct API)
    ("deser_yaml_safe_load",
     'config = yaml.safe_load(file_content)',
     "python", False),

    # json.loads — SAFE (no arbitrary code execution)
    ("deser_json_loads_safe",
     'data = json.loads(request.body)',
     "python", False),

    # ── PATH TRAVERSAL ────────────────────────────────────────────────────
    # String concat with ../ — DANGEROUS
    ("path_traversal_concat",
     'full_path = "/uploads/" + user_path + "/../config"',
     "python", True),

    # Java path with ..\ — DANGEROUS
    ("path_traversal_java",
     r'File f = new File(baseDir + user_input + "\\..\\private");',
     "java", True),

    # os.path.basename sanitisation — SAFE
    ("path_traversal_basename_safe",
     'safe = os.path.join("/uploads", os.path.basename(user_path))',
     "python", False),

    # ── XXE ───────────────────────────────────────────────────────────────
    # ENTITY + SYSTEM declaration — DANGEROUS
    ("xxe_entity_declaration",
     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
     "xml", True),

    # Clean XML with no DOCTYPE — SAFE
    ("xxe_clean_xml_safe",
     '<root><user>Alice</user><role>viewer</role></root>',
     "xml", False),

    # ── HARDCODED SECRETS ─────────────────────────────────────────────────
    # AWS Access Key ID format — DANGEROUS
    ("secret_aws_key",
     'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
     "python", True),

    # Hardcoded password string — DANGEROUS
    ("secret_password_hardcoded",
     'password = "SuperSecret123!"',
     "python", True),

    # PEM private key header — DANGEROUS
    ("secret_private_key",
     '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
     "text", True),

    # Reading from environment — SAFE
    ("secret_env_var_safe",
     'password = os.environ.get("DB_PASSWORD")',
     "python", False),

    # ── INSECURE RANDOMNESS ───────────────────────────────────────────────
    # Math.random() in JavaScript — INSECURE for tokens/session IDs
    ("random_math_random_js",
     'const sessionId = Math.random().toString(36).slice(2);',
     "javascript", True),

    # secrets.token_hex() — SAFE (cryptographically secure)
    ("random_secrets_safe",
     'token = secrets.token_hex(32)',
     "python", False),
]
