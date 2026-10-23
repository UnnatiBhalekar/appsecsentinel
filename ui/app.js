  /* All user-supplied data is rendered with textContent, never innerHTML,
     so a snippet containing <script> tags cannot execute in the results. */

  const API = "";  // same origin; change to "http://localhost:8000" if needed

  // ── Tab switching ─────────────────────────────────────────────────
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    });
  });

  // ── Severity badge helper ─────────────────────────────────────────
  function badge(sev) {
    const el = document.createElement("span");
    el.className = "badge badge-" + sev;
    el.textContent = sev;   // textContent — cannot XSS
    return el;
  }

  // ── Render a list of finding objects ─────────────────────────────
  function renderFindings(findings, container) {
    container.textContent = "";   // clear safely

    if (!findings || findings.length === 0) {
      const p = document.createElement("p");
      p.className = "clean-msg";
      p.textContent = "✅ No issues found.";
      container.appendChild(p);
      return;
    }

    const hdr = document.createElement("p");
    hdr.className = "results-header";
    hdr.textContent = findings.length + " finding(s):";
    container.appendChild(hdr);

    findings.forEach(f => {
      const card = document.createElement("div");
      card.className = "finding-card sev-" + f.severity;

      const top = document.createElement("div");
      top.className = "finding-top";
      top.appendChild(badge(f.severity));

      const ruleEl = document.createElement("span");
      ruleEl.className = "rule-id";
      ruleEl.textContent = f.rule_id;
      top.appendChild(ruleEl);

      const catEl = document.createElement("span");
      catEl.className = "category";
      catEl.textContent = f.owasp_category;
      top.appendChild(catEl);

      card.appendChild(top);

      const msg = document.createElement("p");
      msg.className = "msg";
      msg.textContent = f.message;   // textContent — safe
      card.appendChild(msg);

      if (f.line_number && f.line_number > 0) {
        const ln = document.createElement("p");
        ln.className = "line-no";
        ln.textContent = "Line " + f.line_number;
        card.appendChild(ln);
      }

      container.appendChild(card);
    });
  }

  function showError(container, msg) {
    container.textContent = "";
    const p = document.createElement("p");
    p.className = "error-msg";
    p.textContent = msg;   // textContent — safe
    container.appendChild(p);
  }

  function showSpinner(container) {
    container.textContent = "";
    const p = document.createElement("p");
    p.className = "spinner";
    p.textContent = "Scanning…";
    container.appendChild(p);
  }

  // ── Generic API call ──────────────────────────────────────────────
  async function callApi(endpoint, body, resultsEl, btnEl) {
    showSpinner(resultsEl);
    btnEl.disabled = true;
    try {
      const res = await fetch(API + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(resultsEl, data.error || "Request failed (" + res.status + ").");
        return;
      }
      renderFindings(data.findings, resultsEl);
    } catch (err) {
      showError(resultsEl, "Could not reach the API. Is the server running?");
    } finally {
      btnEl.disabled = false;
    }
  }

  // ── Code tab ──────────────────────────────────────────────────────
  document.getElementById("code-scan-btn").addEventListener("click", () => {
    const code = document.getElementById("code-input").value;
    const lang = document.getElementById("lang-select").value;
    callApi("/api/scan", { code, language: lang },
            document.getElementById("code-results"),
            document.getElementById("code-scan-btn"));
  });

  document.getElementById("code-example-btn").addEventListener("click", () => {
    document.getElementById("lang-select").value = "python";
    document.getElementById("code-input").value =
`import os, pickle, hashlib

def run_query(user_id):
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)

def run_cmd(cmd):
    os.system(cmd)

def load_data(blob):
    return pickle.loads(blob)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
`;
  });

  document.getElementById("code-clear-btn").addEventListener("click", () => {
    document.getElementById("code-input").value = "";
    document.getElementById("code-results").textContent = "";
  });

  // ── JWT tab ───────────────────────────────────────────────────────
  document.getElementById("jwt-scan-btn").addEventListener("click", () => {
    const token = document.getElementById("jwt-input").value;
    callApi("/api/jwt", { token },
            document.getElementById("jwt-results"),
            document.getElementById("jwt-scan-btn"));
  });

  document.getElementById("jwt-example-btn").addEventListener("click", () => {
    // A JWT with alg=none, no exp, no aud — intentionally weak for demo
    document.getElementById("jwt-input").value =
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
      ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9" +
      ".";
  });

  document.getElementById("jwt-clear-btn").addEventListener("click", () => {
    document.getElementById("jwt-input").value = "";
    document.getElementById("jwt-results").textContent = "";
  });

  // ── IAM tab ───────────────────────────────────────────────────────
  document.getElementById("iam-scan-btn").addEventListener("click", () => {
    const policy_json = document.getElementById("iam-input").value;
    callApi("/api/iam", { policy_json },
            document.getElementById("iam-results"),
            document.getElementById("iam-scan-btn"));
  });

  document.getElementById("iam-example-btn").addEventListener("click", () => {
    document.getElementById("iam-input").value = JSON.stringify({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "DangerousAdmin",
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }, null, 2);
  });

  document.getElementById("iam-clear-btn").addEventListener("click", () => {
    document.getElementById("iam-input").value = "";
    document.getElementById("iam-results").textContent = "";
  });
