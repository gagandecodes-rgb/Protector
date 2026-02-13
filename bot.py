import os
import json
import asyncio
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from supabase import create_client, Client
import requests  # For coupon checking

# Set up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Supabase setup
SUPABASE_URL = os.getenv('SUPABASE_URL')  # Set in Render env vars
SUPABASE_KEY = os.getenv('SUPABASE_KEY')  # Set in Render env vars
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Telegram token
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')  # Set in Render env vars

# Function to get user data from Supabase
def get_user_data(user_id):
    response = supabase.table('user_data').select('*').eq('user_id', str(user_id)).execute()
    return response.data[0] if response.data else None

# Function to upsert user data
def upsert_user_data(user_id, data):
    supabase.table('user_data').upsert({'user_id': str(user_id), **data}).execute()

# Placeholder for checking a coupon (replace with actual logic)
def check_coupon(coupon, cookies):
    # Example: Assume an API endpoint that takes a coupon and returns status
    # Inspect the target site for real URL, headers, etc.
    url = 'https://example.com/api/check-coupon'  # Replace with real endpoint
    headers = {'Cookie': '; '.join([f'{k}={v}' for k, v in json.loads(cookies).items()])}
    response = requests.post(url, json={'coupon': coupon}, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get('valid', False)  # Assume response has 'valid': true/false
    return False

# Background task for protection mode
async def protection_task(context: ContextTypes.DEFAULT_TYPE):
    while True:
        # Get all users with protect_active=True
        users = supabase.table('user_data').select('*').eq('protect_active', True).execute()
        for user in users.data:
            user_id = user['user_id']
            cookies = user['cookies']
            coupons = json.loads(user['coupons'])
            results = []
            for coupon in coupons:
                is_valid = check_coupon(coupon, cookies)
                results.append(f"{coupon}: {'Working' if is_valid else 'Not Working'}")
            # Send update to user
            await context.bot.send_message(chat_id=user_id, text="Protection Check:\n" + "\n".join(results))
        await asyncio.sleep(900)  # 15 minutes

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text("Please set your cookies (as JSON, e.g., {\"session\": \"value\"}):")
    context.user_data['awaiting_cookies'] = True

# Handle messages (cookies, coupons)
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text

    if context.user_data.get('awaiting_cookies'):
        try:
            cookies = json.loads(text)
            upsert_user_data(user_id, {'cookies': json.dumps(cookies)})
            await update.message.reply_text("Cookies set! Now send /check to proceed.")
            context.user_data['awaiting_cookies'] = False
        except json.JSONDecodeError:
            await update.message.reply_text("Invalid JSON. Try again.")
    elif context.user_data.get('awaiting_coupons'):
        # Assume coupons are sent as newline-separated text
        coupons = text.split('\n')
        user_data = get_user_data(user_id)
        if not user_data or not user_data['cookies']:
            await update.message.reply_text("Set cookies first with /start.")
            return
        cookies = user_data['cookies']
        results = []
        for coupon in coupons:
            coupon = coupon.strip()
            if coupon:
                is_valid = check_coupon(coupon, cookies)
                results.append(f"{coupon}: {'Working' if is_valid else 'Not Working'}")
        # Store coupons
        upsert_user_data(user_id, {'coupons': json.dumps(coupons)})
        await update.message.reply_text("Results:\n" + "\n".join(results))
        context.user_data['awaiting_coupons'] = False

# /check command
async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_data = get_user_data(update.effective_user.id)
    if not user_data or not user_data['cookies']:
        await update.message.reply_text("Set cookies first with /start.")
        return
    await update.message.reply_text("Send coupons (one per line or as a file):")
    context.user_data['awaiting_coupons'] = True

# Handle file uploads (for coupons)
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    file = await update.message.document.get_file()
    content = await file.download_as_bytearray()
    text = content.decode('utf-8')
    # Treat as handle_message for coupons
    context.user_data['awaiting_coupons'] = True
    update.message.text = text  # Simulate text message
    await handle_message(update, context)

# /protect command
async def protect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    upsert_user_data(user_id, {'protect_active': True})
    await update.message.reply_text("Protection enabled. Rechecking every 15 minutes.")

# /removeprotect command
async def removeprotect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    upsert_user_data(user_id, {'protect_active': False})
    await update.message.reply_text("Protection disabled.")

# Main function
def main():
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    # Handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("check", check))
    application.add_handler(CommandHandler("protect", protect))
    application.add_handler(CommandHandler("removeprotect", removeprotect))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    # Start protection task
    application.job_queue.run_repeating(protection_task, interval=900, first=10)

    # Run bot
    application.run_polling()

if __name__ == '__main__':
    main()
