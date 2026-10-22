"""
core/iam_auditor.py
-------------------
AWS IAM policy least-privilege auditor.

Parses a policy JSON document and returns structured Finding objects so
callers can process results programmatically before formatting them as text.
"""

import json
from .models import Finding, SEVERITY_ORDER


class PolicyError(Exception):
    """Raised when the policy document is structurally invalid."""


# Permissions that alone can enable privilege escalation.
# Source: AWS privilege-escalation research (Rhino Security Labs, AWS docs).
_PRIV_ESC_SINGLETONS: set[str] = {
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "sts:AssumeRole",
}

# Permissions that, combined with iam:PassRole, allow privilege escalation.
_PRIV_ESC_WITH_PASSROLE: set[str] = {
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "glue:CreateDevEndpoint",
    "sagemaker:CreateTrainingJob",
}

# Services whose wildcard actions carry the highest risk in a financial context.
_HIGH_RISK_SERVICES: set[str] = {
    "iam", "sts", "kms", "secretsmanager", "s3", "ec2", "lambda",
}


def audit_policy(policy_json: str) -> tuple[list[Finding], dict]:
    """
    Parse and audit an AWS IAM policy document.

    Returns (findings, metadata) where metadata contains:
      n_statements — number of Allow statements analysed

    Raises PolicyError on malformed JSON or a missing Statement block.
    """
    try:
        policy: dict = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise PolicyError(
            f"Error: Invalid JSON — could not parse the IAM policy. "
            f"Detail: {exc.msg} at line {exc.lineno}."
        )

    statements = policy.get("Statement")
    if statements is None:
        raise PolicyError(
            "No 'Statement' block found in the policy. "
            "Ensure this is a valid IAM policy document."
        )

    if len(statements) == 0:
        return [], {"n_statements": 0}

    issues: list[tuple[str, str, str]] = []  # (rule_id, severity, message)

    for idx, stmt in enumerate(statements, start=1):
        label = f"Statement[{idx}] (Sid: {stmt.get('Sid', 'unnamed')})"
        effect = stmt.get("Effect", "Allow")

        if effect != "Allow":
            continue  # Deny statements narrow permissions — not a risk

        raw_actions = stmt.get("Action", [])
        actions: list[str] = [raw_actions] if isinstance(raw_actions, str) else raw_actions

        raw_resources = stmt.get("Resource", [])
        resources: list[str] = [raw_resources] if isinstance(raw_resources, str) else raw_resources

        conditions: dict = stmt.get("Condition", {})
        action_set = {a.lower() for a in actions}
        has_wildcard_action = "*" in actions

        # 1. Wildcard action (AdministratorAccess equivalent)
        if has_wildcard_action:
            issues.append(("IAM-001", "CRITICAL",
                f"{label}: Action is '*' (AdministratorAccess equivalent). "
                "This grants every permission in every AWS service. "
                "Replace with the specific actions this principal actually requires."))

        # 2. Service-level wildcard on high-risk services
        for action in actions:
            if action.endswith(":*"):
                service = action.split(":")[0].lower()
                sev = "CRITICAL" if service in _HIGH_RISK_SERVICES else "HIGH"
                risk_note = (
                    f"HIGH RISK service — {service.upper()} controls IAM/secrets/encryption. "
                    if service in _HIGH_RISK_SERVICES else ""
                )
                issues.append(("IAM-002", sev,
                    f"{label}: Service-level wildcard '{action}' violates least-privilege. "
                    f"{risk_note}"
                    "Replace with only the specific actions required."))

        # 3. Wildcard resource with no condition
        if "*" in resources and not conditions:
            issues.append(("IAM-003", "HIGH",
                f"{label}: Resource is '*' with no Condition block. "
                "Scope resources to specific ARNs and add conditions "
                "(e.g. aws:RequestedRegion, aws:SourceAccount) to limit blast radius."))

        # 4. Privilege-escalation singletons
        for dangerous in _PRIV_ESC_SINGLETONS:
            if dangerous.lower() in action_set or has_wildcard_action:
                issues.append(("IAM-004", "CRITICAL",
                    f"{label}: Contains '{dangerous}' — this permission alone can enable "
                    "privilege escalation (e.g. creating new admin credentials or attaching "
                    "broader policies). Ensure this is intentional and tightly scoped."))

        # 5. iam:PassRole + execution service combination
        if "iam:passrole" in action_set or has_wildcard_action:
            for exec_action in _PRIV_ESC_WITH_PASSROLE:
                if exec_action.lower() in action_set or has_wildcard_action:
                    issues.append(("IAM-005", "CRITICAL",
                        f"{label}: Dangerous combination — 'iam:PassRole' + '{exec_action}'. "
                        "An attacker can pass a high-privilege role to a compute resource "
                        "they control, granting themselves escalated permissions. "
                        "Restrict iam:PassRole with a condition on iam:PassedToService."))
                    break  # one warning per statement is enough

        # 6. Sensitive actions with no MFA condition
        sensitive = {"iam:*", "sts:assumerole", "s3:deleteobject", "s3:deletebucket"}
        if action_set & sensitive and not conditions:
            issues.append(("IAM-006", "MEDIUM",
                f"{label}: Sensitive action(s) present with no MFA condition. "
                "Add 'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}} "
                "for human-facing roles accessing sensitive resources."))

    findings = [
        Finding(rule_id=rid, severity=sev, owasp_category="A01 Broken Access Control",
                message=msg, line_number=0)
        for rid, sev, msg in sorted(issues, key=lambda x: SEVERITY_ORDER.get(x[1], 9))
    ]

    return findings, {"n_statements": len(statements)}


def format_iam_report(findings: list[Finding], metadata: dict) -> str:
    """Render IAM audit results as a human-readable text report."""
    n = metadata["n_statements"]

    if n == 0:
        return (
            "✅ IAM policy has an empty Statement array — no permissions are granted. "
            "Verify this is intentional."
        )

    if not findings:
        return (
            "✅ No least-privilege violations detected in this IAM policy.\n\n"
            "Good practice: Continue to review policies against AWS IAM Access Analyzer "
            "and rotate unused permissions regularly."
        )

    lines = [
        "🔐 IAM POLICY AUDIT REPORT",
        "=" * 45,
        f"Statements analysed : {n}",
        f"Findings            : {len(findings)}",
    ]

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            lines.append(f"\n[{f.severity}]")
            current_sev = f.severity
        lines.append(f"  • {f.message}")

    lines.append(
        f"\n{'─' * 45}\n"
        "Remediation approach:\n"
        "  1. Replace wildcard actions with specific action lists.\n"
        "  2. Scope Resource to specific ARNs (arn:aws:s3:::my-bucket/*).\n"
        "  3. Add Condition blocks to limit by IP, MFA, region, or account.\n"
        "  4. Run AWS IAM Access Analyzer to catch cross-account exposure.\n"
        "  5. Apply the principle of least privilege: grant only what is needed,\n"
        "     when it is needed, to the identity that needs it."
    )

    return "\n".join(lines)
