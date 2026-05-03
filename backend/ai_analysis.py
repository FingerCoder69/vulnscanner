import urllib.request
import json
import os

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-3-5-sonnet-20240620"


def _call_claude(prompt: str, max_tokens: int = 800) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    payload = json.dumps({
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
        "system": (
            "You are a senior penetration tester writing concise, actionable security reports. "
            "Be direct. Use technical language. No fluff. Format output as clean JSON only — "
            "no markdown fences, no preamble."
        ),
    }).encode()

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        print(f"[ai_analysis] Claude API HTTP error: {e.code} - {e.read().decode()}")
        return json.dumps({
            "summary": "AI analysis unavailable",
            "exploit_scenario": "N/A",
            "fix": "See OWASP guidelines",
            "cvss_justification": "N/A",
            "attack_payloads": [],
        })
    except Exception as e:
        print(f"[ai_analysis] Claude API error: {e}")
        return json.dumps({
            "summary": "AI analysis unavailable",
            "exploit_scenario": "N/A",
            "fix": "See OWASP guidelines",
            "cvss_justification": "N/A",
            "attack_payloads": [],
        })


def analyze_finding(finding: dict) -> dict:
    """Ask Claude to triage a single DAST or network finding."""
    prompt = f"""
Analyze this vulnerability finding and return a JSON object with these exact keys:
- "summary": 1-2 sentence plain-English explanation of WHY this is dangerous
- "exploit_scenario": concrete step-by-step attack scenario (3-4 steps max)
- "fix": specific remediation code or config snippet (not generic advice)
- "cvss_justification": why this severity/score is accurate
- "attack_payloads": list of 3 additional payloads an attacker would try next

Finding:
{json.dumps(finding, indent=2)}

Return ONLY valid JSON. No markdown. No extra text.
"""
    raw = _call_claude(prompt)
    try:
        return json.loads(raw)
    except Exception:
        return {
            "summary": "Analysis parsing failed",
            "exploit_scenario": raw[:300],
            "fix": "See OWASP guidelines",
            "cvss_justification": "",
            "attack_payloads": [],
        }


def analyze_port(entry: dict) -> dict:
    """Ask Claude to triage a network port finding with CVEs."""
    prompt = f"""
You are a senior penetration tester. Analyze this network service and its CVEs.
Return ONLY a JSON object with these exact keys:
- "risk_summary": 2 sentence plain-English explanation of the overall risk
- "most_dangerous_cve": the CVE ID that poses the biggest threat and why (1 sentence)
- "exploit_scenario": concrete 3-step attack scenario an attacker would use
- "fix": the single most important remediation action
- "attack_commands": array of 2-3 example commands/tools an attacker would run (e.g. nmap, metasploit, hydra)

Service data:
{json.dumps(entry, indent=2)}

Return ONLY valid JSON. No markdown. No extra text.
"""
    raw = _call_claude(prompt)
    try:
        return json.loads(raw)
    except Exception:
        return {
            "risk_summary": raw[:300],
            "most_dangerous_cve": "N/A",
            "exploit_scenario": "N/A",
            "fix": "See OWASP guidelines",
            "attack_commands": [],
        }


def generate_report(scan_result: dict) -> str:
    """Ask Claude to write a full professional pentest report."""
    prompt = f"""
Write a professional penetration test report for this DAST scan.

Scan data:
{json.dumps(scan_result, indent=2)}

Return a JSON object with these keys:
- "executive_summary": 2-3 sentences for non-technical management
- "risk_rating": overall rating (Critical/High/Medium/Low/Informational)
- "key_findings": array of objects, each with "title", "impact", "recommendation"
- "attack_surface": brief description of the attack surface observed
- "immediate_actions": list of 3 things to fix right now
- "conclusion": 2-sentence closing statement

Return ONLY valid JSON. No markdown fences.
"""
    raw = _call_claude(prompt, max_tokens=1200)
    try:
        parsed = json.loads(raw)
        return parsed
    except Exception:
        return {"executive_summary": raw[:500], "error": "Parsing failed"}
