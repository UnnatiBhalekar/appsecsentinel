# INTENTIONALLY VULNERABLE — for demo and CI gate testing only.
# This file exists to show AppSecSentinel detecting real issues.
# Do NOT deploy or import this code.

import os
import hashlib
import sqlite3


def get_user(user_id):
    # VULN 1: SQL injection — user input concatenated directly into query string.
    # Safe alternative: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)
    return cursor.fetchone()


def run_report(report_name):
    # VULN 2: Command injection — unsanitised variable passed to os.system.
    # Safe alternative: subprocess.run(["generate_report", report_name], check=True)
    os.system("generate_report " + report_name)


def store_password(password):
    # VULN 3: Weak hashing — MD5 is cryptographically broken for passwords.
    # Safe alternative: bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashlib.md5(password.encode()).hexdigest()
