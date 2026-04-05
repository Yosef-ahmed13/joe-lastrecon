#!/usr/bin/env python3
"""
severity_scorer.py — Analyze recon findings and assign severity scores
"""
import sys, re, json

SEVERITY_RULES = [
    # (pattern, score, label, description)
    (r'(?i)(remote.code.exec|rce|command.inject)', 10, "🔴 CRITICAL", "RCE / Command Injection"),
    (r'(?i)(sql.inject|sqli|union.select)', 10, "🔴 CRITICAL", "SQL Injection"),
    (r'(?i)(stored.xss|blind.xss)', 9, "🔴 CRITICAL", "Stored/Blind XSS"),
    (r'(?i)(server.side.template|ssti)', 9, "🔴 CRITICAL", "SSTI"),
    (r'(?i)(deserialization)', 9, "🔴 CRITICAL", "Insecure Deserialization"),
    (r'(?i)(ssrf|server.side.request)', 8, "🟠 HIGH", "SSRF"),
    (r'(?i)(local.file.include|lfi|path.traversal)', 8, "🟠 HIGH", "LFI / Path Traversal"),
    (r'(?i)(xxe|xml.external)', 8, "🟠 HIGH", "XXE"),
    (r'(?i)(reflected.xss|xss)', 7, "🟠 HIGH", "Reflected XSS"),
    (r'(?i)(open.redirect)', 7, "🟠 HIGH", "Open Redirect"),
    (r'(?i)(subdomain.takeover|takeover)', 7, "🟠 HIGH", "Subdomain Takeover"),
    (r'(?i)(cors.misconfiguration|cors)', 6, "🟡 MEDIUM", "CORS Misconfiguration"),
    (r'(?i)(exposed.api.key|api.key.leak)', 6, "🟡 MEDIUM", "API Key Exposed"),
    (r'(?i)(sensitive.file|backup.file|\.bak|\.sql|\.env)', 6, "🟡 MEDIUM", "Sensitive File Exposed"),
    (r'(?i)(admin.panel|admin.login)', 5, "🟡 MEDIUM", "Admin Panel Found"),
    (r'(?i)(default.cred|default.password)', 5, "🟡 MEDIUM", "Default Credentials"),
    (r'(?i)(directory.listing|directory.index)', 5, "🟡 MEDIUM", "Directory Listing"),
    (r'(?i)(missing.hsts|missing.csp|security.header)', 3, "🔵 LOW", "Missing Security Headers"),
    (r'(?i)(information.disclosure|version.disclosure)', 3, "🔵 LOW", "Information Disclosure"),
    (r'(?i)(waf.bypass)', 4, "🔵 LOW", "WAF Bypass"),
    (r'(?i)(alive|200 OK|status.*200)', 2, "⚪ INFO", "Live Host"),
    (r'(?i)(subdomain|\.)', 1, "⚪ INFO", "Subdomain Found"),
]

def score_line(line):
    for pattern, score, label, desc in SEVERITY_RULES:
        if re.search(pattern, line):
            return score, label, desc
    return 1, "⚪ INFO", "Finding"

def analyze_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                score, label, desc = score_line(line)
                findings.append({
                    "finding": line[:150],
                    "score": score,
                    "severity": label,
                    "type": desc
                })
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    return findings

def format_telegram_output(findings, tool_name=""):
    if not findings:
        return ""
    
    # Sort by severity descending
    findings.sort(key=lambda x: x["score"], reverse=True)
    
    # Group by severity
    groups = {}
    for f in findings:
        key = f["severity"]
        groups.setdefault(key, []).append(f)
    
    lines = []
    if tool_name:
        lines.append(f"<b>📊 {tool_name} Results</b>")
    
    for sev in ["🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM", "🔵 LOW", "⚪ INFO"]:
        if sev in groups:
            items = groups[sev]
            lines.append(f"\n{sev} ({len(items)} findings):")
            for item in items[:10]:  # max 10 per category in message
                lines.append(f"  [{item['score']}/10] {item['finding'][:80]}")
            if len(items) > 10:
                lines.append(f"  ... +{len(items)-10} more (see file)")
    
    return "\n".join(lines)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: severity_scorer.py <results_file> [tool_name]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    tool_name = sys.argv[2] if len(sys.argv) > 2 else ""
    
    findings = analyze_file(filepath)
    
    if "--json" in sys.argv:
        print(json.dumps(findings, indent=2))
    else:
        output = format_telegram_output(findings, tool_name)
        print(output)
