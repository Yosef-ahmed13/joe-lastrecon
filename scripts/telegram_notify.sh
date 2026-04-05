#!/bin/bash
# ─────────────────────────────────────────────────────
# telegram_notify.sh — Send messages/files to Telegram
# ─────────────────────────────────────────────────────

BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
CHAT_ID="${TELEGRAM_CHAT_ID}"
TG_BASE="https://api.telegram.org/bot${BOT_TOKEN}"

tg_msg() {
    local text="$1"
    local parse_mode="${2:-HTML}"
    curl -s -X POST "${TG_BASE}/sendMessage" \
        -d chat_id="${CHAT_ID}" \
        -d parse_mode="${parse_mode}" \
        -d text="${text}" \
        -d disable_web_page_preview=true > /dev/null 2>&1
}

tg_file() {
    local filepath="$1"
    local caption="$2"
    if [[ -f "$filepath" && -s "$filepath" ]]; then
        curl -s -X POST "${TG_BASE}/sendDocument" \
            -F chat_id="${CHAT_ID}" \
            -F document=@"${filepath}" \
            -F caption="${caption}" > /dev/null 2>&1
    fi
}

tg_code() {
    local title="$1"
    local content="$2"
    local max_len=3500
    if [[ ${#content} -gt $max_len ]]; then
        content="${content:0:$max_len}\n...truncated"
    fi
    tg_msg "<b>${title}</b>\n<pre>${content}</pre>"
}

# Severity badge
severity_badge() {
    local score=$1
    if   [[ $score -ge 9 ]]; then echo "🔴 CRITICAL"
    elif [[ $score -ge 7 ]]; then echo "🟠 HIGH"
    elif [[ $score -ge 5 ]]; then echo "🟡 MEDIUM"
    elif [[ $score -ge 3 ]]; then echo "🔵 LOW"
    else echo "⚪ INFO"
    fi
}

# Usage: $1 = function name, rest = args
case "$1" in
    msg)  tg_msg "$2" "$3" ;;
    file) tg_file "$2" "$3" ;;
    code) tg_code "$2" "$3" ;;
    *)    tg_msg "$1" ;;
esac
