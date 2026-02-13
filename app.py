import os
import re
import time
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

import asyncpg
import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# =========================================================
# ENV
# =========================================================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip()           # https://your-service.onrender.com
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()   # random secret string
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()       # Supabase Postgres URL
COOKIE_SECRET = os.getenv("COOKIE_SECRET", "").strip()     # random long string
CHECK_INTERVAL_MINUTES = int(os.getenv("CHECK_INTERVAL_MINUTES", "15"))
SCHEDULER_POLL_SECONDS = int(os.getenv("SCHEDULER_POLL_SECONDS", "60"))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN missing")
if not PUBLIC_URL:
    raise RuntimeError("PUBLIC_URL missing")
if not WEBHOOK_SECRET:
    raise RuntimeError("WEBHOOK_SECRET missing")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL missing")
if not COOKIE_SECRET:
    raise RuntimeError("COOKIE_SECRET missing")

# =========================================================
# SIMPLE SECURITY: encrypt cookies before storing
# (Recommended since cookies are sensitive)
# =========================================================
def _derive_fernet_key(secret: str) -> bytes:
    raw = secret.encode("utf-8")
    raw = raw[:32].ljust(32, b"\0")
    return base64.urlsafe_b64encode(raw)

FERNET = Fernet(_derive_fernet_key(COOKIE_SECRET))

def encrypt_cookie(cookie: str) -> str:
    return FERNET.encrypt(cookie.encode("utf-8")).decode("utf-8")

def decrypt_cookie(cookie_enc: str) -> str:
    return FERNET.decrypt(cookie_enc.encode("utf-8")).decode("utf-8")

# =========================================================
# DB
# =========================================================
pool: Optional[asyncpg.Pool] = None

async def db_init():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)

async def ensure_user(user_id: int):
    async with pool.acquire() as con:
        await con.execute(
            "insert into public.tg_users(user_id) values($1) on conflict do nothing",
            user_id
        )

async def set_user_cookie(user_id: int, cookie_plain: str):
    await ensure_user(user_id)
    enc = encrypt_cookie(cookie_plain)
    async with pool.acquire() as con:
        await con.execute(
            """
            insert into public.user_cookies(user_id, cookie_enc)
            values($1, $2)
            on conflict (user_id)
            do update set cookie_enc=excluded.cookie_enc, updated_at=now()
            """,
            user_id, enc
        )

async def delete_user_cookie(user_id: int):
    async with pool.acquire() as con:
        await con.execute("delete from public.user_cookies where user_id=$1", user_id)

async def get_user_cookie(user_id: int) -> Optional[str]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "select cookie_enc from public.user_cookies where user_id=$1",
            user_id
        )
    if not row:
        return None
    return decrypt_cookie(row["cookie_enc"])

def normalize_code(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\s+", "", text)
    return text

def status_emoji(status: str) -> str:
    return {"valid": "✅", "invalid": "❌", "unknown": "⚠️"}.get(status, "⚠️")

# =========================================================
# SHEIN CHECKER (YOU MUST PLUG YOUR REAL METHOD)
# - This function receives the USER'S cookie.
# - Keep it light: do not spam.
# =========================================================
async def check_shein_code_with_cookie(code: str, cookie: str) -> Dict[str, Any]:
    """
    Implement using your captured request from DevTools.
    Return:
      {"status":"valid"/"invalid"/"unknown", "details":"..."}
    """

    # ---- PLACEHOLDER (so bot runs) ----
    # Replace this with real SHEIN request logic.
    if len(code) < 6:
        return {"status": "invalid", "details": "Too short (placeholder)."}
    return {"status": "unknown", "details": "Checker not configured yet. Plug real SHEIN request."}

# =========================================================
# Telegram Bot
# =========================================================
fastapi_app = FastAPI()
tg_app: Optional[Application] = None

# Users who are currently in "waiting for cookie message" mode
COOKIE_WAITING = set()

# ---------------- Commands ----------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "👋 SHEIN Code Checker + Protector Bot\n\n"
        "Setup:\n"
        "1) /setcookie (paste your SHEIN cookie)\n"
        "2) Send a code → I will check\n"
        "3) If you want auto-check: /protect CODE\n\n"
        "Commands:\n"
        "/setcookie - upload cookie (1 message)\n"
        "/delcookie - delete cookie\n"
        "/protect CODE - enable protection\n"
        "/remove CODE - remove protected code\n"
        "/mycodes - list protected codes\n"
        "/check CODE - check code now\n"
    )

async def setcookie_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    COOKIE_WAITING.add(user_id)
    await update.message.reply_text(
        "🧾 Send your SHEIN cookie string now (paste in ONE message).\n\n"
        "Tip: Browser → DevTools → Network → pick any request → Headers → Cookie.\n"
        "After you send it, I will store it encrypted."
    )

async def delcookie_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    await delete_user_cookie(user_id)
    await update.message.reply_text("✅ Cookie deleted.")

async def protect_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Usage: /protect CODE")
        return

    cookie = await get_user_cookie(user_id)
    if not cookie:
        await update.message.reply_text("❌ Set your cookie first: /setcookie")
        return

    code = normalize_code("".join(context.args))
    await ensure_user(user_id)

    async with pool.acquire() as con:
        await con.execute(
            """
            insert into public.protected_codes(user_id, code, next_check_at)
            values($1, $2, now())
            on conflict (user_id, code) do update
              set next_check_at = now()
            """,
            user_id, code
        )

    await update.message.reply_text(f"🛡️ Protection enabled for `{code}`.", parse_mode="Markdown")

async def remove_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Usage: /remove CODE")
        return

    code = normalize_code("".join(context.args))
    async with pool.acquire() as con:
        await con.execute(
            "delete from public.protected_codes where user_id=$1 and code=$2",
            user_id, code
        )

    await update.message.reply_text(f"Removed `{code}` (if it existed).", parse_mode="Markdown")

async def mycodes_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            select code, last_status, next_check_at
            from public.protected_codes
            where user_id=$1
            order by next_check_at asc
            """,
            user_id
        )

    if not rows:
        await update.message.reply_text("No protected codes. Use /protect CODE")
        return

    lines = ["🛡️ Your protected codes:"]
    for r in rows:
        st = r["last_status"]
        lines.append(f"- `{r['code']}` → {status_emoji(st)} *{st.upper()}* (next: {r['next_check_at']})")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")

async def check_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Usage: /check CODE")
        return
    code = normalize_code("".join(context.args))

    cookie = await get_user_cookie(user_id)
    if not cookie:
        await update.message.reply_text("❌ Set your cookie first: /setcookie")
        return

    msg = await update.message.reply_text(f"🔎 Checking `{code}` ...", parse_mode="Markdown")
    try:
        result = await check_shein_code_with_cookie(code, cookie)
        st = result.get("status", "unknown")
        details = result.get("details", "")
        await msg.edit_text(
            f"Result for `{code}`: {status_emoji(st)} *{st.upper()}*\n{details}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await msg.edit_text(f"❌ Check failed: {e}")

# ---------------- Text Handler ----------------
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return

    user_id = update.effective_user.id
    text = update.message.text.strip()

    # 1) Cookie capture flow
    if user_id in COOKIE_WAITING:
        COOKIE_WAITING.remove(user_id)
        cookie_text = text

        await set_user_cookie(user_id, cookie_text)

        # Optional: delete cookie message to reduce exposure
        try:
            await context.bot.delete_message(
                chat_id=update.effective_chat.id,
                message_id=update.message.message_id
            )
        except:
            pass

        await update.effective_chat.send_message("✅ Cookie saved. Now send a code or use /check CODE.")
        return

    # 2) If user just sends a code directly -> do a check now
    if text.startswith("/"):
        return

    code = normalize_code(text)
    cookie = await get_user_cookie(user_id)
    if not cookie:
        await update.message.reply_text("❌ Set your cookie first: /setcookie")
        return

    msg = await update.message.reply_text(f"🔎 Checking `{code}` ...", parse_mode="Markdown")
    try:
        result = await check_shein_code_with_cookie(code, cookie)
        st = result.get("status", "unknown")
        details = result.get("details", "")
        await msg.edit_text(
            f"Result for `{code}`: {status_emoji(st)} *{st.upper()}*\n{details}\n\n"
            f"If you want auto-check every {CHECK_INTERVAL_MINUTES} minutes:\n"
            f"Use: /protect {code}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await msg.edit_text(f"❌ Check failed: {e}")

# =========================================================
# Scheduler: runs globally and checks only DUE codes
# =========================================================
async def scheduler_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    now = datetime.now(timezone.utc)

    # Fetch due items (limit to avoid overload)
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            select pc.id, pc.user_id, pc.code, pc.last_status, uc.cookie_enc
            from public.protected_codes pc
            join public.user_cookies uc on uc.user_id = pc.user_id
            where pc.next_check_at <= now()
            order by pc.next_check_at asc
            limit 50
            """
        )

    if not rows:
        return

    for r in rows:
        code_id = r["id"]
        user_id = int(r["user_id"])
        code = r["code"]
        old_status = r["last_status"] or "unknown"

        try:
            cookie_plain = decrypt_cookie(r["cookie_enc"])
            result = await check_shein_code_with_cookie(code, cookie_plain)
            new_status = result.get("status", "unknown")
            details = result.get("details", "")

            next_time = now + timedelta(minutes=CHECK_INTERVAL_MINUTES)

            async with pool.acquire() as con:
                await con.execute(
                    """
                    update public.protected_codes
                    set last_status=$1,
                        last_checked_at=now(),
                        next_check_at=$2
                    where id=$3
                    """,
                    new_status, next_time, code_id
                )

            # Notify only on change
            if new_status != old_status:
                await context.bot.send_message(
                    chat_id=user_id,
                    text=(
                        f"🛡️ Protection update\n"
                        f"Code: `{code}`\n"
                        f"Status: {status_emoji(new_status)} *{new_status.upper()}* (was {old_status})\n"
                        f"{details}"
                    ),
                    parse_mode="Markdown"
                )

        except Exception as e:
            # Even if check fails, push next_check_at forward (avoid tight error loop)
            next_time = now + timedelta(minutes=CHECK_INTERVAL_MINUTES)
            async with pool.acquire() as con:
                await con.execute(
                    """
                    update public.protected_codes
                    set last_checked_at=now(),
                        next_check_at=$1
                    where id=$2
                    """,
                    next_time, code_id
                )
            try:
                await context.bot.send_message(
                    chat_id=user_id,
                    text=f"⚠️ Protection check failed for `{code}`: {e}",
                    parse_mode="Markdown"
                )
            except:
                pass

# =========================================================
# FastAPI Webhook
# =========================================================
@fastapi_app.on_event("startup")
async def on_startup():
    global tg_app
    await db_init()

    tg_app = Application.builder().token(BOT_TOKEN).build()

    tg_app.add_handler(CommandHandler("start", start_cmd))
    tg_app.add_handler(CommandHandler("setcookie", setcookie_cmd))
    tg_app.add_handler(CommandHandler("delcookie", delcookie_cmd))
    tg_app.add_handler(CommandHandler("protect", protect_cmd))
    tg_app.add_handler(CommandHandler("remove", remove_cmd))
    tg_app.add_handler(CommandHandler("mycodes", mycodes_cmd))
    tg_app.add_handler(CommandHandler("check", check_cmd))
    tg_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    await tg_app.initialize()
    await tg_app.start()

    # Start scheduler
    tg_app.job_queue.run_repeating(
        scheduler_job,
        interval=SCHEDULER_POLL_SECONDS,
        first=10,
        name="global_scheduler"
    )

    # Set webhook
    webhook_url = f"{PUBLIC_URL}/webhook/{WEBHOOK_SECRET}"
    await tg_app.bot.set_webhook(webhook_url)
    print("Webhook set to:", webhook_url)

@fastapi_app.on_event("shutdown")
async def on_shutdown():
    global tg_app
    if tg_app:
        await tg_app.stop()
        await tg_app.shutdown()

@fastapi_app.get("/")
async def root():
    return {"ok": True, "message": "Bot is running."}

@fastapi_app.post("/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request):
    if secret != WEBHOOK_SECRET:
        return {"ok": False, "error": "bad secret"}

    data = await request.json()
    update = Update.de_json(data, tg_app.bot)
    await tg_app.process_update(update)
    return {"ok": True}
