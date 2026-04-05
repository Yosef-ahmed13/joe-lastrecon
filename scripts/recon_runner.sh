#!/bin/bash
# ════════════════════════════════════════════════════════════════
#   recon_runner.sh — Main Recon Pipeline for joe-lastrecon
#   Controlled via Telegram | Results sent back to Telegram
# ════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Paths ───────────────────────────────────────────────────────
TOOLS_DIR="$HOME/go/bin"
WORDLIST_DIR="/usr/share/wordlists"
RESULTS="/tmp/recon_results"
mkdir -p "$RESULTS"
export PATH="$PATH:$TOOLS_DIR:/usr/local/bin"

# ── Source notify helper ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/telegram_notify.sh"

# ── Input ───────────────────────────────────────────────────────
DOMAIN_INPUT="${1:-}"
DOMAINS_FILE="${2:-}"
RUN_ID="${3:-$(date +%s)}"

# Build domain list
DOMAIN_LIST="$RESULTS/domains_input.txt"
if [[ -n "$DOMAINS_FILE" && -f "$DOMAINS_FILE" ]]; then
    cp "$DOMAINS_FILE" "$DOMAIN_LIST"
elif [[ -n "$DOMAIN_INPUT" ]]; then
    echo "$DOMAIN_INPUT" | tr ',' '\n' | sed '/^$/d' > "$DOMAIN_LIST"
fi

TOTAL=$(wc -l < "$DOMAIN_LIST" 2>/dev/null || echo 0)

# ── Start notification ──────────────────────────────────────────
tg_msg "$(cat <<EOF
🚀 <b>joe-lastrecon STARTED</b>
━━━━━━━━━━━━━━━━━━━━━━
🎯 Target(s): <code>${DOMAIN_INPUT:-file upload}</code>
📋 Total domains: <b>${TOTAL}</b>
🔢 Run ID: <code>${RUN_ID}</code>
⏰ Started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
━━━━━━━━━━━━━━━━━━━━━━
🔄 Pipeline: Enum → DNS → HTTP → Ports → Crawl → Vulns
EOF
)"

# ════════════════════════════════════════════════════════════════
# PHASE 1: SUBDOMAIN ENUMERATION
# ════════════════════════════════════════════════════════════════
tg_msg "📡 <b>Phase 1/6: Subdomain Enumeration</b>\n🔍 Running: subfinder, assetfinder, findomain, amass, crt.sh, wayback, github-subdomains..."

ALL_SUBS="$RESULTS/all_subdomains_raw.txt"
> "$ALL_SUBS"

run_on_domains() {
    local domains_file="$1"
    local batch_size=30
    local total_domains=$(wc -l < "$domains_file")
    local batch_num=0
    
    while IFS= read -r domain; do
        batch_num=$((batch_num + 1))
        DOMAIN_RESULT="$RESULTS/${domain}_subs.txt"
        > "$DOMAIN_RESULT"

        # ── Subfinder ──
        if command -v subfinder &>/dev/null; then
            subfinder -d "$domain" -silent -all \
                -provider-config "$SCRIPT_DIR/../provider.yaml" 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── Assetfinder ──
        if command -v assetfinder &>/dev/null; then
            assetfinder --subs-only "$domain" 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── Findomain ──
        if command -v findomain &>/dev/null; then
            findomain -t "$domain" -q 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── crt.sh ──
        curl -s --max-time 30 "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null \
            | python3 -c "import sys,json; data=json.load(sys.stdin); [print(x['name_value']) for x in data]" 2>/dev/null \
            | sed 's/\*\.//g' | sort -u \
            | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true

        # ── Wayback Machine ──
        curl -s --max-time 30 "http://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey" 2>/dev/null \
            | grep -oP '(?<=://)[^/]+' | sort -u \
            | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true

        # ── VirusTotal ──
        if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
            curl -s --max-time 30 \
                "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VIRUSTOTAL_API_KEY}&domain=${domain}" 2>/dev/null \
                | python3 -c "import sys,json; d=json.load(sys.stdin); [print(x) for x in d.get('subdomains',[])]" 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── github-subdomains ──
        if command -v github-subdomains &>/dev/null && [[ -n "${GITHUB_RECON_TOKEN:-}" ]]; then
            github-subdomains -d "$domain" -t "$GITHUB_RECON_TOKEN" -raw 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── shosubgo ──
        if command -v shosubgo &>/dev/null && [[ -n "${SHODAN_API_KEY:-}" ]]; then
            shosubgo -d "$domain" -s "$SHODAN_API_KEY" 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── Chaos ──
        if command -v chaos &>/dev/null && [[ -n "${CHAOS_KEY:-}" ]]; then
            chaos -d "$domain" -silent -key "$CHAOS_KEY" 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        # ── Amass (passive only, fast) ──
        if command -v amass &>/dev/null; then
            timeout 120 amass enum -passive -d "$domain" -silent 2>/dev/null \
                | anew "$DOMAIN_RESULT" >> "$ALL_SUBS" || true
        fi

        COUNT=$(wc -l < "$DOMAIN_RESULT" 2>/dev/null || echo 0)
        tg_msg "✅ <b>${domain}</b> → <code>${COUNT}</code> subdomains found [${batch_num}/${total_domains}]"

    done < "$domains_file"
}

run_on_domains "$DOMAIN_LIST"

TOTAL_SUBS=$(sort -u "$ALL_SUBS" | wc -l)
sort -u "$ALL_SUBS" > "$RESULTS/all_subdomains.txt"

# ── AlterX permutations ──
if command -v alterx &>/dev/null && [[ $TOTAL_SUBS -gt 0 ]]; then
    tg_msg "🔀 <b>Running AlterX</b> (permutations)..."
    alterx -l "$RESULTS/all_subdomains.txt" -silent 2>/dev/null \
        | anew "$RESULTS/all_subdomains.txt" || true
    TOTAL_SUBS=$(wc -l < "$RESULTS/all_subdomains.txt")
fi

tg_msg "$(cat <<EOF
📡 <b>Phase 1 Complete — Subdomain Enum</b>
━━━━━━━━━━━━━━━━━━
📊 Total unique subdomains: <b>${TOTAL_SUBS}</b>
EOF
)"
tg_file "$RESULTS/all_subdomains.txt" "📋 All Raw Subdomains (${TOTAL_SUBS})"

# ════════════════════════════════════════════════════════════════
# PHASE 2: DNS RESOLUTION
# ════════════════════════════════════════════════════════════════
tg_msg "🌐 <b>Phase 2/6: DNS Resolution</b>\n🔍 Using dnsx to filter alive domains..."

RESOLVED="$RESULTS/resolved.txt"
if command -v dnsx &>/dev/null; then
    dnsx -l "$RESULTS/all_subdomains.txt" -silent -a -aaaa -cname \
        -resp -o "$RESOLVED" 2>/dev/null || true
else
    cp "$RESULTS/all_subdomains.txt" "$RESOLVED"
fi

TOTAL_RESOLVED=$(wc -l < "$RESOLVED" 2>/dev/null || echo 0)
# Extract just hostnames
grep -oP '^[^\s\[]+' "$RESOLVED" | sort -u > "$RESULTS/resolved_hosts.txt" 2>/dev/null || cp "$RESOLVED" "$RESULTS/resolved_hosts.txt"

tg_msg "🌐 <b>Phase 2 Complete — DNS Resolution</b>\n✅ Alive domains: <b>$(wc -l < "$RESULTS/resolved_hosts.txt")</b>"

# ════════════════════════════════════════════════════════════════
# PHASE 3: HTTP PROBING
# ════════════════════════════════════════════════════════════════
tg_msg "🌍 <b>Phase 3/6: HTTP Probing</b>\n🔍 Using httpx to find live web servers..."

LIVE_HOSTS="$RESULTS/live_hosts.txt"
HTTPX_FULL="$RESULTS/httpx_full.txt"

if command -v httpx &>/dev/null; then
    httpx -l "$RESULTS/resolved_hosts.txt" -silent \
        -title -status-code -content-length -tech-detect \
        -follow-redirects -timeout 10 \
        -o "$HTTPX_FULL" 2>/dev/null || true
    grep -oP 'https?://[^\s]+' "$HTTPX_FULL" | sort -u > "$LIVE_HOSTS" 2>/dev/null || true
else
    cat "$RESULTS/resolved_hosts.txt" | sed 's/^/https:\/\//' > "$LIVE_HOSTS"
fi

TOTAL_LIVE=$(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)

# Score with severity
HTTPX_SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$HTTPX_FULL" "HTTPx Probe" 2>/dev/null || echo "")

tg_msg "$(cat <<EOF
🌍 <b>Phase 3 Complete — HTTP Probe</b>
━━━━━━━━━━━━━━━━━━
🟢 Live web hosts: <b>${TOTAL_LIVE}</b>
EOF
)"
[[ -n "$HTTPX_SCORE" ]] && tg_msg "$HTTPX_SCORE"
tg_file "$LIVE_HOSTS" "🌍 Live Web Hosts (${TOTAL_LIVE})"

# ── asnmap for ASN info ──
if command -v asnmap &>/dev/null && [[ $TOTAL_LIVE -gt 0 ]]; then
    asnmap -l "$RESULTS/resolved_hosts.txt" -silent -o "$RESULTS/asn_info.txt" 2>/dev/null || true
fi

# ── aquatone screenshots ──
if command -v aquatone &>/dev/null && [[ $TOTAL_LIVE -gt 0 ]]; then
    tg_msg "📸 <b>Taking screenshots with Aquatone...</b>"
    mkdir -p "$RESULTS/screenshots"
    cat "$LIVE_HOSTS" | aquatone -out "$RESULTS/screenshots" -timeout 30 -silent 2>/dev/null || true
    tg_msg "📸 Screenshots saved (available in artifacts)"
fi

# ════════════════════════════════════════════════════════════════
# PHASE 4: PORT SCANNING
# ════════════════════════════════════════════════════════════════
tg_msg "🔌 <b>Phase 4/6: Port Scanning</b>\n🔍 Using naabu + nmap..."

OPEN_PORTS="$RESULTS/open_ports.txt"
> "$OPEN_PORTS"

if command -v naabu &>/dev/null; then
    naabu -l "$RESULTS/resolved_hosts.txt" \
        -p "80,443,8080,8443,8888,3000,5000,4443,9200,6379,27017,3306,5432,22,21,25,110,993,995,3389,8081,8082,9090,9091,9443" \
        -silent -o "$OPEN_PORTS" 2>/dev/null || true
fi

TOTAL_PORTS=$(wc -l < "$OPEN_PORTS" 2>/dev/null || echo 0)
PORT_SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$OPEN_PORTS" "Port Scan" 2>/dev/null || echo "")

tg_msg "🔌 <b>Phase 4 Complete — Port Scan</b>\n🔓 Open ports found: <b>${TOTAL_PORTS}</b>"
[[ -n "$PORT_SCORE" ]] && tg_msg "$PORT_SCORE"
tg_file "$OPEN_PORTS" "🔌 Open Ports"

# ════════════════════════════════════════════════════════════════
# PHASE 5: WEB CRAWLING & URL COLLECTION
# ════════════════════════════════════════════════════════════════
tg_msg "🕷️ <b>Phase 5/6: Web Crawling & URL Collection</b>\n🔍 katana, hakrawler, gau, urlfinder, waybackurls..."

ALL_URLS="$RESULTS/all_urls.txt"
> "$ALL_URLS"

if [[ $TOTAL_LIVE -gt 0 ]]; then

    # ── Katana ──
    if command -v katana &>/dev/null; then
        katana -l "$LIVE_HOSTS" -silent -d 3 -jc -kf all \
            -o "$RESULTS/katana_urls.txt" 2>/dev/null || true
        cat "$RESULTS/katana_urls.txt" 2>/dev/null | anew "$ALL_URLS" || true
    fi

    # ── Hakrawler ──
    if command -v hakrawler &>/dev/null; then
        cat "$LIVE_HOSTS" | hakrawler -d 3 -subs 2>/dev/null \
            | anew "$ALL_URLS" || true
    fi

    # ── GAU (Get All URLs) ──
    if command -v gau &>/dev/null; then
        cat "$RESULTS/resolved_hosts.txt" | gau --subs --timeout 30 2>/dev/null \
            | anew "$ALL_URLS" || true
    fi

    # ── urlfinder ──
    if command -v urlfinder &>/dev/null; then
        urlfinder -l "$LIVE_HOSTS" -silent 2>/dev/null \
            | anew "$ALL_URLS" || true
    fi
fi

# Deduplicate with uro
CLEAN_URLS="$RESULTS/clean_urls.txt"
if command -v uro &>/dev/null; then
    uro -i "$ALL_URLS" -o "$CLEAN_URLS" 2>/dev/null || cp "$ALL_URLS" "$CLEAN_URLS"
else
    sort -u "$ALL_URLS" > "$CLEAN_URLS"
fi

TOTAL_URLS=$(wc -l < "$CLEAN_URLS" 2>/dev/null || echo 0)

# ── GF Patterns ──
GF_RESULTS="$RESULTS/gf_patterns"
mkdir -p "$GF_RESULTS"
if command -v gf &>/dev/null; then
    for pattern in xss sqli ssrf lfi rce redirect debug_logic idor ssti; do
        gf "$pattern" "$CLEAN_URLS" 2>/dev/null > "$GF_RESULTS/${pattern}.txt" || true
        COUNT=$(wc -l < "$GF_RESULTS/${pattern}.txt" 2>/dev/null || echo 0)
        [[ $COUNT -gt 0 ]] && tg_msg "🎯 <b>GF ${pattern^^}</b>: <code>${COUNT}</code> potential targets" || true
    done
fi

tg_msg "🕷️ <b>Phase 5 Complete — Crawling</b>\n🔗 Total URLs collected: <b>${TOTAL_URLS}</b>"
tg_file "$CLEAN_URLS" "🔗 All URLs (${TOTAL_URLS})"

# ════════════════════════════════════════════════════════════════
# PHASE 6: VULNERABILITY SCANNING
# ════════════════════════════════════════════════════════════════
tg_msg "💥 <b>Phase 6/6: Vulnerability Scanning</b>\n🔍 nuclei, dalfox, subzy, Corsy, arjun, ffuf..."

VULN_RESULTS="$RESULTS/vulnerabilities.txt"
> "$VULN_RESULTS"

# ── Subzy (Subdomain Takeover) ──
if command -v subzy &>/dev/null; then
    tg_msg "🎯 Checking subdomain takeovers (subzy)..."
    SUBZY_OUT="$RESULTS/subzy.txt"
    subzy run --targets "$RESULTS/all_subdomains.txt" --hide_fails \
        --output "$SUBZY_OUT" 2>/dev/null || true
    if [[ -s "$SUBZY_OUT" ]]; then
        cat "$SUBZY_OUT" >> "$VULN_RESULTS"
        SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$SUBZY_OUT" "Subzy Takeover")
        tg_msg "$SCORE"
        tg_file "$SUBZY_OUT" "⚠️ Subdomain Takeover Results"
    fi
fi

# ── CORS Check ──
tg_msg "🌐 Checking CORS misconfigurations..."
CORS_OUT="$RESULTS/cors.txt"
> "$CORS_OUT"
while IFS= read -r url; do
    origin="https://evil.com"
    result=$(curl -s --max-time 10 -H "Origin: $origin" -I "$url" 2>/dev/null | grep -i "access-control-allow-origin" | grep -i "evil.com" || true)
    [[ -n "$result" ]] && echo "CORS: $url — $result" | tee -a "$CORS_OUT" >> "$VULN_RESULTS"
done < "$LIVE_HOSTS"
[[ -s "$CORS_OUT" ]] && tg_file "$CORS_OUT" "🌐 CORS Misconfigurations"

# ── XSS Detection ──
if command -v dalfox &>/dev/null && [[ -f "$GF_RESULTS/xss.txt" ]] && [[ -s "$GF_RESULTS/xss.txt" ]]; then
    tg_msg "💉 Running Dalfox (XSS scanner)..."
    DALFOX_OUT="$RESULTS/dalfox.txt"
    dalfox file "$GF_RESULTS/xss.txt" --silence --no-color \
        --skip-bav -o "$DALFOX_OUT" 2>/dev/null || true
    if [[ -s "$DALFOX_OUT" ]]; then
        cat "$DALFOX_OUT" >> "$VULN_RESULTS"
        SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$DALFOX_OUT" "DalFox XSS")
        tg_msg "$SCORE"
        tg_file "$DALFOX_OUT" "💉 XSS Findings (DalFox)"
    fi
fi

# ── KXSS / Gxss ──
if command -v kxss &>/dev/null && [[ -f "$GF_RESULTS/xss.txt" ]]; then
    cat "$GF_RESULTS/xss.txt" | kxss 2>/dev/null > "$RESULTS/kxss.txt" || true
    [[ -s "$RESULTS/kxss.txt" ]] && tg_file "$RESULTS/kxss.txt" "🔍 KXSS Reflections"
fi

if command -v Gxss &>/dev/null && [[ -f "$GF_RESULTS/xss.txt" ]]; then
    cat "$GF_RESULTS/xss.txt" | Gxss 2>/dev/null > "$RESULTS/gxss.txt" || true
fi

# ── Nuclei ──
if command -v nuclei &>/dev/null && [[ $TOTAL_LIVE -gt 0 ]]; then
    tg_msg "☢️ Running Nuclei (full template scan)..."
    NUCLEI_OUT="$RESULTS/nuclei.txt"

    nuclei -l "$LIVE_HOSTS" \
        -s critical,high,medium \
        -silent -no-color \
        -etags dos \
        -timeout 10 \
        -rl 50 \
        -o "$NUCLEI_OUT" 2>/dev/null || true

    if [[ -s "$NUCLEI_OUT" ]]; then
        cat "$NUCLEI_OUT" >> "$VULN_RESULTS"
        SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$NUCLEI_OUT" "Nuclei Scanner")
        tg_msg "$SCORE"
        tg_file "$NUCLEI_OUT" "☢️ Nuclei Vulnerabilities"
    else
        tg_msg "☢️ Nuclei: No critical/high/medium findings."
    fi
fi

# ── Arjun (Parameter Discovery) ──
if command -v arjun &>/dev/null && [[ $TOTAL_LIVE -gt 0 ]]; then
    tg_msg "🔎 Running Arjun (hidden parameter discovery)..."
    ARJUN_OUT="$RESULTS/arjun_params.txt"
    head -20 "$LIVE_HOSTS" | while IFS= read -r url; do
        arjun -u "$url" -oT "$ARJUN_OUT" --quiet 2>/dev/null || true
    done
    [[ -s "$ARJUN_OUT" ]] && tg_file "$ARJUN_OUT" "🔎 Hidden Parameters (Arjun)"
fi

# ── Dirsearch ──
if command -v dirsearch &>/dev/null && [[ $TOTAL_LIVE -gt 0 ]]; then
    tg_msg "📂 Running Dirsearch (directory brute-force)..."
    DIRSEARCH_OUT="$RESULTS/dirsearch.txt"
    head -5 "$LIVE_HOSTS" | while IFS= read -r url; do
        dirsearch -u "$url" -e php,asp,aspx,jsp,html,json,xml,txt,bak,sql \
            -t 20 --quiet -o "$DIRSEARCH_OUT" 2>/dev/null || true
    done
    if [[ -s "$DIRSEARCH_OUT" ]]; then
        SCORE=$(python3 "$SCRIPT_DIR/severity_scorer.py" "$DIRSEARCH_OUT" "Dirsearch")
        tg_msg "$SCORE"
        tg_file "$DIRSEARCH_OUT" "📂 Directories Found"
    fi
fi

# ── WPScan (WordPress) ──
if command -v wpscan &>/dev/null; then
    while IFS= read -r url; do
        if curl -s --max-time 10 "$url" 2>/dev/null | grep -qi "wp-content\|wordpress"; then
            tg_msg "🔧 WordPress detected on $url — running WPScan..."
            wpscan --url "$url" --no-banner --random-user-agent \
                -o "$RESULTS/wpscan_$(echo $url | tr '/:' '_').txt" 2>/dev/null || true
        fi
    done < "$LIVE_HOSTS"
fi

# ════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════
TOTAL_VULNS=$(wc -l < "$VULN_RESULTS" 2>/dev/null || echo 0)

# Count by severity
CRITICAL=$(grep -c "CRITICAL\|critical\|rce\|sqli" "$VULN_RESULTS" 2>/dev/null || echo 0)
HIGH=$(grep -c "HIGH\|high\|xss\|ssrf\|lfi" "$VULN_RESULTS" 2>/dev/null || echo 0)
MEDIUM=$(grep -c "MEDIUM\|medium\|cors\|takeover" "$VULN_RESULTS" 2>/dev/null || echo 0)

tg_msg "$(cat <<EOF
🏁 <b>RECON COMPLETE — joe-lastrecon</b>
━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: <code>${DOMAIN_INPUT:-multiple domains}</code>
🔢 Run ID: <code>${RUN_ID}</code>
━━━━━━━━━━━━━━━━━━━━━━━━
📡 Subdomains found:  <b>${TOTAL_SUBS}</b>
🌍 Live web hosts:   <b>${TOTAL_LIVE}</b>
🔌 Open ports:       <b>${TOTAL_PORTS}</b>
🔗 URLs collected:   <b>${TOTAL_URLS}</b>
💥 Vulnerabilities:  <b>${TOTAL_VULNS}</b>
━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL: ${CRITICAL}
🟠 HIGH:     ${HIGH}
🟡 MEDIUM:   ${MEDIUM}
━━━━━━━━━━━━━━━━━━━━━━━━
✅ All files uploaded to GitHub Artifacts
⏰ Finished: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
EOF
)"

tg_file "$VULN_RESULTS" "💥 All Vulnerabilities Combined"

echo "::set-output name=total_subs::${TOTAL_SUBS}"
echo "::set-output name=total_live::${TOTAL_LIVE}"
echo "::set-output name=total_vulns::${TOTAL_VULNS}"
