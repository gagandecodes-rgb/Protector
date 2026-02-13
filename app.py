import os
import re
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

import asyncpg
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
    JobQueue,
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
# Encrypt cookies before storing (recommended)
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

# =========================================================
# Helpers
# =========================================================
def normalize_code(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\s+", "", text)
    return text

def status_emoji(status: str) -> str:
    return {"valid": "✅", "invalid": "❌", "unknown": "⚠️"}.get(status, "⚠️")

# =========================================================
# SHEIN CHECKER (placeholder — replace with real method)
# =========================================================
import httpx

SHEIN_APPLY_VOUCHER_URL = "https://www.sheinindia.in/api/cart/apply-voucher"

async def check_shein_code_with_cookie(code: str, cookie: str) -> Dict[str, Any]:
    """
    Checks a SHEIN voucher by calling the same endpoint as the website.

    Returns:
      {"status":"valid"/"invalid"/"unknown", "details":"..."}
    """

    # Minimal headers needed (copied from your curl, but trimmed)
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "origin": "https://www.sheinindia.in",
        "referer": "https://www.sheinindia.in/cart",
        "user-agent": "Mozilla/5.0",
        "x-tenant-id": "SHEIN",
        "cookie": cookie,   # <-- IMPORTANT: use the user's cookie here
    }

    payload = {
        "voucherId": code,
        "device": {"client_type": "web"}
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(SHEIN_APPLY_VOUCHER_URL, headers=headers, json=payload)

        # Try parse JSON (SHEIN usually replies JSON even on errors)
        try:
            data = r.json()
        except Exception:
            data = None

        # --- Interpret result ---
        # Most common:
        # - 200 => applied (valid)
        # - 400 => invalid/expired/not eligible
        # - 401/403 => cookie expired/blocked
        # - 429 => rate limited

        if r.status_code == 200:
            # Often contains discount info; show small details safely
            details = ""
            if isinstance(data, dict):
                # try common keys
                msg = data.get("msg") or data.get("message") or data.get("tip")
                if msg:
                    details = str(msg)
                else:
                    details = "Applied successfully."
            else:
                details = "Applied successfully."
            return {"status": "valid", "details": details}

        if r.status_code == 400:
            # Usually invalid/expired/not applicable
            msg = ""
            if isinstance(data, dict):
                msg = data.get("msg") or data.get("message") or data.get("tip") or ""
                # Sometimes error nested
                if not msg and isinstance(data.get("info"), dict):
                    msg = data["info"].get("msg") or data["info"].get("message") or ""
            if not msg:
                msg = "Invalid / not applicable (HTTP 400)."
            return {"status": "invalid", "details": msg}

        if r.status_code in (401, 403):
            return {"status": "unknown", "details": "Cookie expired / not authorized. Please /setcookie again."}

        if r.status_code == 429:
            return {"status": "unknown", "details": "Rate limited by SHEIN (429). Try later."}

        # Fallback
        preview = ""
        if isinstance(data, dict):
            preview = str(data)[:300]
        else:
            preview = (r.text or "")[:300]

        return {"status": "unknown", "details": f"HTTP {r.status_code}. {preview}"}

    except httpx.TimeoutException:
        return {"status": "unknown", "details": "Timeout contacting SHEIN. Try again."}
    except Exception as e:
        return {"status": "unknown", "details": f"Checker error: {e}"}

# =========================================================
# Telegram Bot + FastAPI Webhook
# =========================================================
fastapi_app = FastAPI()
tg_app: Optional[Application] = None

COOKIE_WAITING = set()

# ---------------- Commands ----------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "👋 SHEIN Code Checker + Protector Bot\n\n"
        "Setup:\n"
        "1) /setcookie (paste your SHEIN cookie)\n"
        "2) Send a code → I will check\n"
        "3) Enable auto-check: /protect CODE\n\n"
        "Commands:\n"
        "/setcookie - upload cookie\n"
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
        "Browser → DevTools → Network → choose request → Headers → Cookie"
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

    # Cookie capture flow
    if user_id in COOKIE_WAITING:
        COOKIE_WAITING.remove(user_id)
        await set_user_cookie(user_id, text)

        # Try to delete the message with cookie (privacy)
        try:
            await context.bot.delete_message(
                chat_id=update.effective_chat.id,
                message_id=update.message.message_id
            )
        except:
            pass

        await update.effective_chat.send_message("✅ Cookie saved. Now send a code or use /check CODE.")
        return

    if text.startswith("/"):
        return

    # If user sends a code directly
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
            f"Enable auto-check every {CHECK_INTERVAL_MINUTES} minutes:\n"
            f"Use: /protect {code}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await msg.edit_text(f"❌ Check failed: {e}")

# =========================================================
# Scheduler: checks ONLY DUE codes from DB
# =========================================================
async def scheduler_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    now = datetime.now(timezone.utc)

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
            # push next_check_at forward to avoid tight error loop
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
# FastAPI Webhook endpoints
# =========================================================
@fastapi_app.on_event("startup")
async def on_startup():
    global tg_app
    await db_init()

    # ✅ FIX: explicitly attach a JobQueue
    jq = JobQueue()
    tg_app = Application.builder().token(BOT_TOKEN).job_queue(jq).build()

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

    # scheduler
    tg_app.job_queue.run_repeating(
        scheduler_job,
        interval=SCHEDULER_POLL_SECONDS,
        first=10,
        name="global_scheduler"
    )

    # webhook
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
