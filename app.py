import os
import re
import json
import time
import sqlite3
import hashlib
import hmac
import logging
from typing import List, Dict, Optional, Tuple

import requests
from fastapi import FastAPI, Request, Header, HTTPException
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes, filters
)

# ---------------- ENV ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")  # e.g. https://your-bot.onrender.com
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-me").strip()

# Your validator service URL (from previous step)
# Example: https://your-validator.onrender.com/validate
VALIDATOR_VALIDATE_URL = os.getenv("VALIDATOR_VALIDATE_URL", "").strip()

DB_PATH = os.getenv("DB_PATH", "bot.db")

PROTECT_INTERVAL_SECONDS = 15 * 60
SCAN_EVERY_SECONDS = 60
MAX_COUPONS_PER_RUN = 300

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("tg-validator-bot")

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN missing")
if not PUBLIC_URL:
    raise SystemExit("PUBLIC_URL missing")
if not WEBHOOK_SECRET:
    raise SystemExit("WEBHOOK_SECRET missing")
if not VALIDATOR_VALIDATE_URL:
    raise SystemExit("VALIDATOR_VALIDATE_URL missing (your validator /validate endpoint)")

# ---------------- DB ----------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS user_tokens (
        user_id INTEGER PRIMARY KEY,
        token TEXT,
        updated_at INTEGER
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS protect_lists (
        user_id INTEGER PRIMARY KEY,
        coupons_json TEXT,
        enabled INTEGER NOT NULL DEFAULT 0,
        last_run_at INTEGER DEFAULT 0,
        last_result_hash TEXT DEFAULT ''
    )""")
    conn.commit()
    conn.close()

def set_token(user_id: int, token: str):
    conn = db()
    conn.execute(
        "INSERT INTO user_tokens(user_id, token, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET token=excluded.token, updated_at=excluded.updated_at",
        (user_id, token, int(time.time()))
    )
    conn.commit()
    conn.close()

def get_token(user_id: int) -> Optional[str]:
    conn = db()
    cur = conn.execute("SELECT token FROM user_tokens WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def set_protect_list(user_id: int, coupons: List[str], enabled: bool):
    conn = db()
    conn.execute(
        "INSERT INTO protect_lists(user_id, coupons_json, enabled, last_run_at) VALUES(?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET coupons_json=excluded.coupons_json, enabled=excluded.enabled",
        (user_id, json.dumps(coupons), 1 if enabled else 0, int(time.time()) if enabled else 0)
    )
    conn.commit()
    conn.close()

def get_protect_rows():
    conn = db()
    cur = conn.execute("SELECT user_id, coupons_json, last_run_at, last_result_hash FROM protect_lists WHERE enabled=1")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_protect_list(user_id: int) -> Tuple[List[str], bool, int, str]:
    conn = db()
    cur = conn.execute("SELECT coupons_json, enabled, last_run_at, last_result_hash FROM protect_lists WHERE user_id=?",
                       (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return [], False, 0, ""
    return json.loads(row[0] or "[]"), bool(row[1]), int(row[2] or 0), row[3] or ""

def update_protect_run(user_id: int, last_run_at: int, result_hash: str):
    conn = db()
    conn.execute(
        "UPDATE protect_lists SET last_run_at=?, last_result_hash=? WHERE user_id=?",
        (last_run_at, result_hash, user_id)
    )
    conn.commit()
    conn.close()

# ---------------- PARSE ----------------
COUPON_RE = re.compile(r"[A-Za-z0-9_\-]{4,64}")

def parse_coupons(text: str) -> List[str]:
    raw = re.split(r"[\r\n,\s]+", (text or "").strip())
    out, seen = [], set()
    for x in raw:
        x = x.strip()
        if not x:
            continue
        if not COUPON_RE.fullmatch(x):
            continue
        c = x.upper()
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def chunk(items: List[str], n: int) -> List[List[str]]:
    return [items[i:i+n] for i in range(0, len(items), n)]

def stable_hash(obj) -> str:
    s = json.dumps(obj, sort_keys=True)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ---------------- VALIDATOR CALL ----------------
def call_validator(user_token: str, coupons: List[str]) -> List[Dict]:
    """
    Calls your validator service:
    POST VALIDATOR_VALIDATE_URL with {token, coupons}
    Expected response:
      {"results":[{"code":"X","working":true,"reason":"ok"}, ...]}
    """
    r = requests.post(
        VALIDATOR_VALIDATE_URL,
        json={"token": user_token, "coupons": coupons},
        timeout=30
    )
    r.raise_for_status()
    data = r.json()
    results = data.get("results", [])
    # normalize to ensure each coupon exists in output
    mp = {str(x.get("code", "")).upper(): x for x in results}
    out = []
    for c in coupons:
        x = mp.get(c.upper())
        if not x:
            out.append({"code": c, "working": False, "reason": "no_result"})
        else:
            out.append({
                "code": c,
                "working": bool(x.get("working")),
                "reason": str(x.get("reason", ""))[:200]
            })
    return out

def split_results(results: List[Dict]) -> Tuple[List[str], List[str]]:
    ok = [x["code"] for x in results if x.get("working") is True]
    bad = [x["code"] for x in results if not x.get("working")]
    return ok, bad

# ---------------- WEBHOOK SECURITY ----------------
def verify_secret(provided: str) -> bool:
    return hmac.compare_digest(provided or "", WEBHOOK_SECRET)

# ---------------- BOT STATE ----------------
USER_STATE = {}  # user_id -> WAIT_TOKEN | WAIT_CHECK | WAIT_PROTECT

# ---------------- TELEGRAM HANDLERS ----------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "✅ Bot online.\n\n"
        "Commands:\n"
        "/setcookies - set your token (text or file)\n"
        "/check - send coupons to check\n"
        "/protect - protect list (re-check every 15 min)\n"
        "/remprotect - stop protection\n"
    )

async def setcookies_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    USER_STATE[update.effective_user.id] = "WAIT_TOKEN"
    await update.message.reply_text("Send your token now (text or .txt file).")

async def check_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not get_token(uid):
        await update.message.reply_text("❌ No token saved. Use /setcookies first.")
        return
    USER_STATE[uid] = "WAIT_CHECK"
    await update.message.reply_text("Send coupons now (text or .txt file).")

async def protect_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not get_token(uid):
        await update.message.reply_text("❌ No token saved. Use /setcookies first.")
        return
    USER_STATE[uid] = "WAIT_PROTECT"
    await update.message.reply_text("Send coupons to protect (text or .txt file).")

async def remprotect_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    coupons, enabled, _, _ = get_protect_list(uid)
    if not enabled:
        await update.message.reply_text("ℹ️ Protection already OFF.")
        return
    set_protect_list(uid, coupons, enabled=False)
    await update.message.reply_text("✅ Protection stopped.")

async def handle_text_or_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    state = USER_STATE.get(uid)

    # read input
    if update.message.document:
        doc = update.message.document
        if doc.file_size and doc.file_size > 2_000_000:
            await update.message.reply_text("❌ File too large (max 2MB).")
            return
        f = await doc.get_file()
        b = await f.download_as_bytearray()
        text = b.decode("utf-8", errors="ignore").strip()
    else:
        text = (update.message.text or "").strip()

    if not text:
        await update.message.reply_text("❌ Empty input.")
        return

    if state == "WAIT_TOKEN":
        set_token(uid, text)
        USER_STATE.pop(uid, None)
        await update.message.reply_text("✅ Token saved.")
        return

    if state == "WAIT_CHECK":
        USER_STATE.pop(uid, None)
        coupons = parse_coupons(text)[:MAX_COUPONS_PER_RUN]
        if not coupons:
            await update.message.reply_text("❌ No coupons found.")
            return

        token = get_token(uid) or ""
        await update.message.reply_text(f"⏳ Checking {len(coupons)} coupons...")

        results = []
        try:
            for batch in chunk(coupons, 50):
                results.extend(call_validator(token, batch))
        except Exception as e:
            await update.message.reply_text(f"❌ Validator error: {type(e).__name__}")
            return

        ok, bad = split_results(results)
        await update.message.reply_text(f"✅ Done\n\n🟢 WORKING: {len(ok)}\n🔴 NOT WORKING: {len(bad)}")

        async def send_list(title: str, arr: List[str]):
            if not arr:
                return
            for i in range(0, len(arr), 50):
                await update.message.reply_text(title + "\n" + "\n".join(arr[i:i+50]))

        await send_list("🟢 WORKING CODES:", ok[:200])
        await send_list("🔴 NOT WORKING CODES:", bad[:200])
        return

    if state == "WAIT_PROTECT":
        USER_STATE.pop(uid, None)
        coupons = parse_coupons(text)[:MAX_COUPONS_PER_RUN]
        if not coupons:
            await update.message.reply_text("❌ No coupons found.")
            return
        set_protect_list(uid, coupons, enabled=True)
        await update.message.reply_text(f"✅ Protection enabled for {len(coupons)} coupons (checks every 15 minutes).")
        return

    await update.message.reply_text("Use /setcookies, /check, or /protect.")

# ---------------- FASTAPI APP (Webhook Receiver) ----------------
api = FastAPI()
tg_app: Optional[Application] = None

@api.get("/")
async def root():
    return {"ok": True, "service": "telegram-validator-bot"}

@api.post("/webhook")
async def webhook(request: Request, x_webhook_secret: str = Header(default="")):
    if not verify_secret(x_webhook_secret):
        raise HTTPException(status_code=401, detail="Unauthorized")

    data = await request.json()
    upd = Update.de_json(data, tg_app.bot)  # type: ignore
    await tg_app.process_update(upd)        # type: ignore
    return {"ok": True}

# ---------------- PROTECTION JOB ----------------
async def protection_tick(context: ContextTypes.DEFAULT_TYPE):
    now = int(time.time())
    for (user_id, coupons_json, last_run_at, last_hash) in get_protect_rows():
        user_id = int(user_id)
        last_run_at = int(last_run_at or 0)
        if now - last_run_at < PROTECT_INTERVAL_SECONDS:
            continue

        token = get_token(user_id)
        if not token:
            # disable if missing token
            coupons = json.loads(coupons_json or "[]")
            set_protect_list(user_id, coupons, enabled=False)
            continue

        coupons = (json.loads(coupons_json or "[]") or [])[:MAX_COUPONS_PER_RUN]
        if not coupons:
            set_protect_list(user_id, [], enabled=False)
            continue

        results = []
        try:
            for batch in chunk(coupons, 50):
                results.extend(call_validator(token, batch))
        except Exception:
            update_protect_run(user_id, now, last_hash or "")
            continue

        new_hash = stable_hash(results)
        update_protect_run(user_id, now, new_hash)

        if new_hash != (last_hash or ""):
            ok, bad = split_results(results)
            msg = (
                "🛡️ Protection update (changed)\n\n"
                f"🟢 WORKING: {len(ok)}\n"
                f"🔴 NOT WORKING: {len(bad)}\n"
                f"⏱ Checked: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}"
            )
            try:
                await context.bot.send_message(chat_id=user_id, text=msg)
            except Exception as e:
                log.warning("Notify failed user=%s err=%s", user_id, e)

@api.on_event("startup")
async def startup():
    global tg_app
    init_db()

    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_cmd))
    tg_app.add_handler(CommandHandler("setcookies", setcookies_cmd))
    tg_app.add_handler(CommandHandler("check", check_cmd))
    tg_app.add_handler(CommandHandler("protect", protect_cmd))
    tg_app.add_handler(CommandHandler("remprotect", remprotect_cmd))
    tg_app.add_handler(MessageHandler(filters.TEXT | filters.Document.ALL, handle_text_or_file))

    await tg_app.initialize()
    await tg_app.bot.set_webhook(url=f"{PUBLIC_URL}/webhook", secret_token=WEBHOOK_SECRET)
    await tg_app.start()

    tg_app.job_queue.run_repeating(protection_tick, interval=SCAN_EVERY_SECONDS, first=10)
    log.info("Webhook set: %s/webhook", PUBLIC_URL)

@api.on_event("shutdown")
async def shutdown():
    if tg_app:
        await tg_app.stop()
        await tg_app.shutdown()
