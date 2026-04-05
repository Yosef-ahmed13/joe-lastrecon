# 🕵️ joe-lastrecon

> **Full Automated Recon Pipeline** controlled via Telegram + GitHub Actions

```
[Telegram] ──/recon domain.com──► [bot_listener.py] ──repository_dispatch──► [GitHub Actions]
                                                                                      │
[Telegram] ◄── Live Results (Severity 1-10) ──────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Add GitHub Secrets
Go to `Settings → Secrets and variables → Actions` and add:

| Secret | Required | Description |
|--------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | ✅ | Your bot token |
| `TELEGRAM_CHAT_ID` | ✅ | Your chat ID |
| `GH_TOKEN` | ✅ | GitHub PAT for dispatch |
| `SHODAN_API_KEY` | ⚡ | Better port/host results |
| `CHAOS_KEY` | ⚡ | ProjectDiscovery Chaos |
| `VIRUSTOTAL_API_KEY` | ⚡ | VT subdomain lookup |
| `GITHUB_RECON_TOKEN` | ⚡ | github-subdomains tool |
| `CENSYS_API_ID` | ➕ | Censys search |
| `CENSYS_API_SECRET` | ➕ | Censys search |
| `BINARYEDGE_KEY` | ➕ | BinaryEdge API |
| `SECURITYTRAILS_KEY` | ➕ | SecurityTrails API |
| `FOFA_EMAIL` + `FOFA_KEY` | ➕ | FOFA search |

### 2. Run the Telegram Bot Locally
```bash
pip install -r requirements.txt
python3 bot_listener.py
```

### 3. Start Scanning via Telegram
```
/recon example.com
/recon a.com,b.com,c.com
# OR send a .txt file with one domain per line
```

---

## 📡 Recon Pipeline (6 Phases)

| Phase | Tools | Output |
|-------|-------|--------|
| 1️⃣ Subdomain Enum | subfinder, assetfinder, amass, crt.sh, chaos, shosubgo, github-subdomains, virustotal, wayback | `all_subdomains.txt` |
| 2️⃣ DNS Resolution | dnsx, alterx | `resolved_hosts.txt` |
| 3️⃣ HTTP Probing | httpx, asnmap, aquatone | `live_hosts.txt` |
| 4️⃣ Port Scanning | naabu, nmap | `open_ports.txt` |
| 5️⃣ Web Crawling | katana, hakrawler, gau, urlfinder, gf, uro | `clean_urls.txt` |
| 6️⃣ Vuln Scanning | nuclei, dalfox, subzy, Corsy, kxss, Gxss, arjun, dirsearch, wpscan | `vulnerabilities.txt` |

---

## 🔴 Severity Scoring

| Score | Label | Examples |
|-------|-------|---------|
| 9-10/10 | 🔴 CRITICAL | RCE, SQLi, SSTI, Deserialization |
| 7-8/10 | 🟠 HIGH | SSRF, LFI, XSS, Open Redirect |
| 5-6/10 | 🟡 MEDIUM | Subdomain Takeover, CORS, Exposed Files |
| 3-4/10 | 🔵 LOW | Missing Headers, Info Disclosure |
| 1-2/10 | ⚪ INFO | Live Hosts, Subdomains |

---

## 📦 Batch Processing
- Domains are auto-split into **batches of 30**
- Each batch runs as a **separate GitHub Actions job**
- `anew` deduplicates all results before sending to Telegram

## 🛠️ Tools Installed
subfinder • assetfinder • findomain • amass • alterx • dnsx • httpx • naabu • katana • nuclei • dalfox • subzy • Gxss • kxss • qsreplace • hakrawler • gau • urlfinder • gf • uro • anew • ffuf • arjun • dirsearch • wpscan • asnmap • aquatone • github-subdomains • shosubgo • chaos • nmap • masscan • Corsy • curl
