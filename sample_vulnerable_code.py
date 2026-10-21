# sample_vulnerable_code.py
# ------------------------------------------------------------
# DO NOT USE IN PRODUCTION — intentionally insecure for demo purposes.
# Covers multiple OWASP Top 10 categories so scan_owasp_vulnerabilities
# returns a rich set of findings during an interview demo.
# ------------------------------------------------------------

import os
import pickle
import subprocess
import hashlib

# --- A02: Hardcoded credentials ---
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD    = "password=SuperSecret123"
API_KEY        = "api_key=my-very-long-api-key-value-1234"

# --- A02: Weak cryptography ---
def hash_password(plaintext):
    # BAD: MD5 is cryptographically broken — collisions are trivially computable.
    return hashlib.md5(plaintext.encode()).hexdigest()

# --- A03: SQL Injection ---
def get_user(username):
    # BAD: user input concatenated directly into the query string.
    query = "select * from users where username = '" + username + "'"
    return query

# --- A03: Command Injection ---
def run_report(filename):
    # BAD: shell=True with user-supplied data allows arbitrary command execution.
    subprocess.call("generate_report.sh " + filename, shell=True)

# --- A03: XSS sink ---
def render_comment(comment):
    # BAD: unsanitised user content written directly to the DOM.
    return "<div id='comment'>" + comment + "</div>"
    # In a real JS file this would be: document.getElementById('out').innerHTML = comment;

# --- A08: Insecure Deserialisation ---
def load_session(session_bytes):
    # BAD: pickle.loads on untrusted data allows arbitrary code execution.
    return pickle.loads(session_bytes)

# --- A01: Path Traversal ---
def read_file(user_path):
    # BAD: ../../etc/passwd style input would escape the intended directory.
    full_path = "/var/app/uploads/" + user_path + "/../config"
    with open(full_path) as f:
        return f.read()

# --- Private key material ---
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4EXAMPLE==
-----END RSA PRIVATE KEY-----"""
