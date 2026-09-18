"""
Turns the raw, structured findings from checks.py into a plain-English report
using Claude. Falls back to a simple rule-based summary if no API key is set,
so the tool still works while you're testing it locally.
"""

import os
import json

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
# Override if Anthropic ships a newer/cheaper model by the time you deploy this --
# check https://docs.claude.com/en/docs/about-claude/models for the current list.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")

SYSTEM_PROMPT = """You are a security analyst writing a short, plain-English report for a
small business owner who is not a security expert. You will be given structured findings
from a PASSIVE security check (SSL/TLS, HTTP security headers, email authentication
records). This is NOT a penetration test or full audit -- do not imply it found every
possible vulnerability, and do not make guarantees about the site's overall security.

Write the report with these sections, using clear headings:
1. Overall risk snapshot -- one of Low / Medium / High, with one sentence why.
2. What looks good -- brief, specific.
3. What needs attention -- brief, specific, ranked by severity.
4. Three prioritized next steps -- concrete and actionable, written for someone
   who may need to hand this to a developer or hosting provider.

Keep the whole report under 300 words. Do not use alarmist language. Do not
recommend any specific paid product other than general best practice. End with
one sentence noting this was a passive scan, not a full security audit."""


def _fallback_summary(findings: list) -> str:
    lines = ["## Summary (AI report unavailable -- showing raw results)\n"]
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ordered = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "info"), 3))
    for f in ordered:
        lines.append(f"**{f['name']}** -- status: {f['status'].upper()} (severity: {f.get('severity', 'info')})")
        for d in f["details"]:
            lines.append(f"- {d}")
        lines.append("")
    lines.append("_This was a passive scan only, not a full security audit._")
    return "\n".join(lines)


def generate_report(domain: str, findings: list) -> str:
    if not ANTHROPIC_API_KEY:
        return _fallback_summary(findings)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        user_content = (
            f"Domain checked: {domain}\n\n"
            f"Findings (JSON):\n{json.dumps(findings, indent=2)}"
        )
        message = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=700,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        return message.content[0].text
    except Exception as e:  # noqa: BLE001
        fallback = _fallback_summary(findings)
        return f"_(AI report generation failed: {e}. Showing raw results instead.)_\n\n{fallback}"
