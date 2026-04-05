#!/usr/bin/env python3
"""
bot_listener.py — Telegram Bot Listener for joe-lastrecon
══════════════════════════════════════════════════════════
Run this script locally to bridge Telegram ↔ GitHub Actions.

Usage:
    pip install python-telegram-bot requests
    python3 bot_listener.py

Commands in Telegram:
    /recon example.com              → Single domain scan
    /recon example.com,evil.org     → Multiple domains
    /recon                          → Then send a .txt file with domains
    /status                         → Check latest run status
    /help                           → Show help
"""

import os
import sys
import json
import math
import logging
import asyncio
import tempfile
import requests
from datetime import datetime
from telegram import Update, Bot
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    filters, ContextTypes
)

# ─── CONFIG ────────────────────────────────────────────────────
# Set these in your environment or in a .env file (never hardcode secrets!)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = int(os.getenv("TELEGRAM_CHAT_ID", "0"))
GITHUB_TOKEN       = os.getenv("GH_TOKEN", "")
GITHUB_REPO        = os.getenv("GITHUB_REPO", "Yosef-ahmed13/joe-lastrecon")
BATCH_SIZE         = int(os.getenv("BATCH_SIZE", "30"))

GH_API = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("bot.log")
    ]
)
log = logging.getLogger(__name__)

# ─── AUTH CHECK ────────────────────────────────────────────────
def is_authorized(update: Update) -> bool:
    return update.effective_chat.id == TELEGRAM_CHAT_ID

# ─── GITHUB DISPATCH ───────────────────────────────────────────
def trigger_recon(domains_batch: list, batch_id: int, total_batches: int) -> dict:
    """Trigger a repository_dispatch event to start recon."""
    domains_str = ",".join(d.strip() for d in domains_batch if d.strip())
    payload = {
        "event_type": "recon",
        "client_payload": {
            "domains": domains_str,
            "batch_id": str(batch_id),
            "total_batches": str(total_batches),
            "triggered_at": datetime.utcnow().isoformat(),
        }
    }
    resp = requests.post(
        f"{GH_API}/repos/{GITHUB_REPO}/dispatches",
        headers=GH_HEADERS,
        json=payload,
        timeout=30
    )
    return {"status": resp.status_code, "ok": resp.status_code == 204}

def get_latest_run() -> dict | None:
    """Get the latest workflow run info."""
    resp = requests.get(
        f"{GH_API}/repos/{GITHUB_REPO}/actions/runs",
        headers=GH_HEADERS,
        params={"per_page": 1, "event": "repository_dispatch"},
        timeout=30
    )
    if resp.ok:
        runs = resp.json().get("workflow_runs", [])
        return runs[0] if runs else None
    return None

# ─── COMMAND HANDLERS ──────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    await update.message.reply_html(
        "🕵️ <b>joe-lastrecon Bot</b>\n\n"
        "أهلاً! أنا بوت الـ Recon الخاص بيك.\n\n"
        "<b>الأوامر:</b>\n"
        "  /recon <code>example.com</code> — سكان دومين واحد\n"
        "  /recon <code>a.com,b.com,c.com</code> — سكان متعدد\n"
        "  📄 ابعتلي <b>ملف .txt</b> فيه الدومينات\n"
        "  /status — آخر حالة للـ workflow\n"
        "  /help — مساعدة\n\n"
        "💡 السكان بيتقسم لـ batches من 30 دومين أوتوماتيك"
    )

async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    await update.message.reply_html(
        "🛠 <b>دليل الاستخدام:</b>\n\n"
        "<b>1. سكان دومين واحد:</b>\n"
        "  <code>/recon google.com</code>\n\n"
        "<b>2. سكان عدة دومينات:</b>\n"
        "  <code>/recon a.com,b.com,c.com</code>\n\n"
        "<b>3. رفع ملف:</b>\n"
        "  ابعت ملف <code>.txt</code> فيه الدومينات (كل دومين في سطر)\n\n"
        "<b>4. تابع النتائج:</b>\n"
        "  النتائج بتتبعتلك هنا مباشرة أول ما الـ Action يشتغل\n\n"
        "<b>الأدوات المستخدمة:</b>\n"
        "  subfinder, assetfinder, amass, crt.sh, dnsx, httpx,\n"
        "  naabu, katana, nuclei, dalfox, subzy, Corsy, arjun,\n"
        "  dirsearch, ffuf, gau, gf, alterx, aquatone, + أكثر"
    )

async def cmd_recon(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    
    args = ctx.args
    if not args:
        await update.message.reply_text(
            "⚠️ لازم تكتب الدومين!\n"
            "مثال: /recon example.com\n"
            "أو ابعتلي ملف .txt"
        )
        return
    
    # Parse domains
    raw_input = " ".join(args)
    domains = [d.strip() for d in raw_input.replace(",", "\n").split("\n") if d.strip()]
    
    await _dispatch_domains(update, domains)

async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    
    await update.message.reply_text("⏳ جاري التحقق...")
    
    run = get_latest_run()
    if not run:
        await update.message.reply_text("❌ مافيش runs موجودة.")
        return
    
    status = run.get("status", "unknown")
    conclusion = run.get("conclusion", "—")
    name = run.get("name", "recon")
    created = run.get("created_at", "")[:16].replace("T", " ")
    url = run.get("html_url", "")
    run_id = run.get("id", "")
    
    status_emoji = {
        "completed": "✅" if conclusion == "success" else "❌",
        "in_progress": "🔄",
        "queued": "⏳",
        "waiting": "⏳",
    }.get(status, "❓")
    
    await update.message.reply_html(
        f"{status_emoji} <b>Latest Run:</b> #{run_id}\n"
        f"📋 Status: <code>{status}</code>\n"
        f"🏁 Result: <code>{conclusion}</code>\n"
        f"⏰ Started: {created}\n"
        f"🔗 <a href='{url}'>View on GitHub</a>"
    )

# ─── FILE HANDLER ──────────────────────────────────────────────
async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    
    doc = update.message.document
    if not doc:
        return
    
    fname = doc.file_name or ""
    if not fname.endswith(".txt"):
        await update.message.reply_text("⚠️ ابعتلي ملف .txt فقط!")
        return
    
    await update.message.reply_text("📥 ملف استلمته! جاري المعالجة...")
    
    # Download file
    file = await ctx.bot.get_file(doc.file_id)
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode='wb') as tmp:
        await file.download_to_memory(tmp)
        tmp_path = tmp.name
    
    with open(tmp_path, 'r', errors='ignore') as f:
        content = f.read()
    
    domains = [d.strip() for d in content.replace(",", "\n").split("\n") if d.strip() and not d.startswith("#")]
    
    if not domains:
        await update.message.reply_text("❌ الملف فارغ أو محدش فيه دومينات صالحة!")
        return
    
    await _dispatch_domains(update, domains)

# ─── DISPATCH HELPER ───────────────────────────────────────────
async def _dispatch_domains(update: Update, domains: list):
    total = len(domains)
    total_batches = math.ceil(total / BATCH_SIZE)
    
    preview = ", ".join(domains[:3])
    if total > 3:
        preview += f" +{total-3} more"
    
    await update.message.reply_html(
        f"🚀 <b>بدء الـ Recon!</b>\n\n"
        f"🎯 الدومينات: <code>{preview}</code>\n"
        f"📋 العدد الكلي: <b>{total}</b>\n"
        f"📦 Batches: <b>{total_batches}</b> × {BATCH_SIZE}\n\n"
        f"⏳ جاري تشغيل GitHub Actions...\n"
        f"📲 النتائج هتجيلك هنا تلقائياً!"
    )
    
    success_count = 0
    failed_count = 0
    
    for i in range(total_batches):
        batch = domains[i * BATCH_SIZE : (i + 1) * BATCH_SIZE]
        batch_num = i + 1
        
        log.info(f"Dispatching batch {batch_num}/{total_batches} ({len(batch)} domains)")
        result = trigger_recon(batch, batch_num, total_batches)
        
        if result["ok"]:
            success_count += 1
            await update.message.reply_html(
                f"✅ Batch <b>{batch_num}/{total_batches}</b> triggered!\n"
                f"   <code>{', '.join(batch[:3])}{'...' if len(batch)>3 else ''}</code>"
            )
        else:
            failed_count += 1
            await update.message.reply_text(
                f"❌ Batch {batch_num}/{total_batches} فشل! (HTTP {result['status']})\n"
                f"تحقق من الـ GitHub Token والـ Secrets."
            )
        
        # Small delay between batches to avoid rate limiting
        if i < total_batches - 1:
            await asyncio.sleep(3)
    
    total_url = f"https://github.com/{GITHUB_REPO}/actions"
    await update.message.reply_html(
        f"🎬 <b>كل الـ Batches اتبعتت!</b>\n\n"
        f"✅ نجح: {success_count}/{total_batches}\n"
        f"❌ فشل: {failed_count}/{total_batches}\n\n"
        f"👀 <a href='{total_url}'>تابع النتائج على GitHub</a>"
    )

# ─── TEXT HANDLER (domain without command) ─────────────────────
async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    
    text = (update.message.text or "").strip()
    
    # Auto-detect if it looks like a domain
    import re
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    lines = [l.strip() for l in text.split("\n") if l.strip()]
    domains = [l for l in lines if domain_pattern.match(l.replace(",", "").strip())]
    
    if domains:
        await _dispatch_domains(update, domains)
    else:
        await update.message.reply_html(
            "💬 مش فاهم الأمر. جرب:\n"
            "  /recon example.com\n"
            "  أو ابعت ملف .txt"
        )

# ─── MAIN ──────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════╗
║  joe-lastrecon Telegram Bot Listener     ║
║  Connecting Telegram ↔ GitHub Actions   ║
╚══════════════════════════════════════════╝
""")
    print(f"  Bot Token : {TELEGRAM_BOT_TOKEN[:20]}...")
    print(f"  Chat ID   : {TELEGRAM_CHAT_ID}")
    print(f"  GitHub    : {GITHUB_REPO}")
    print(f"  Batch Size: {BATCH_SIZE} domains\n")
    print("🟢 Bot is running! Send /recon to Telegram to start.\n")
    
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("recon",  cmd_recon))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
