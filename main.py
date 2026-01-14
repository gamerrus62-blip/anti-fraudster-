import os
import asyncio
import base64
import hashlib
from telethon import TelegramClient, events, functions, types, errors
from telethon.sessions import StringSession
from cryptography.fernet import Fernet

# --- ФУНКЦИИ ШИФРОВАНИЯ ---
def generate_key(master_str):
    # Делаем из твоего текста настоящий ключ для шифрования
    key = hashlib.sha256(master_str.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(token, key):
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

# --- ЗАГРУЗКА КОНФИГА ---
def load_cfg():
    conf = {}
    with open('config.txt', 'r') as f:
        for line in f:
            if ':' in line:
                k, v = line.strip().split(':', 1)
                conf[k] = v
    return conf

cfg = load_cfg()
MASTER_KEY = generate_key(cfg['master_key'])
API_ID = int(cfg['api_id'])
API_HASH = cfg['api_hash']
BOT_TOKEN = cfg['bot_token']

# Папка для зашифрованных ключей
if not os.path.exists('vault'): os.makedirs('vault')

# Запуск бота-интерфейса
bot = TelegramClient('bot_manager', API_ID, API_HASH).start(bot_token=BOT_TOKEN)

user_clients = {}
states = {}

# ================= ЛОГИКА ЗАЩИТЫ =================

async def run_guard(client, user_id):
    @client.on(events.NewMessage(chats=777000))
    async def monitor(event):
        msg = event.raw_text.lower()
        if any(word in msg for word in ["login", "вход", "код"]):
            try:
                res = await client(functions.account.GetAuthorizationsRequest())
                killed = 0
                for a in res.authorizations:
                    if not a.current:
                        await client(functions.account.ResetAuthorizationRequest(hash=a.hash))
                        killed += 1
                if killed > 0:
                    await bot.send_message(user_id, f"🚨 **ОБНАРУЖЕН ВХОД!**\n❌ Сессии ({killed} шт.) мгновенно убиты.")
            except: pass

# ================= КОМАНДЫ =================

@bot.on(events.NewMessage(pattern='/start'))
async def start(event):
    uid = event.sender_id
    if uid in user_clients:
        kb = [[types.KeyboardButtonCallback("📊 Статус", b"st")],
              [types.KeyboardButtonCallback("💀 Кикнуть всех", b"kick")],
              [types.KeyboardButtonCallback("❌ Удалить аккаунт", b"del")]]
        await event.respond("🛡 Защита активна. Все данные зашифрованы.", buttons=bot.build_reply_markup(kb))
    else:
        await event.respond("🔐 Твои данные будут зашифрованы ключом из config.txt\nНажми 'Войти'.", 
                           buttons=[[types.KeyboardButtonCallback("🔑 Войти", b"reg")]])

@bot.on(events.CallbackQuery)
async def cb_handler(event):
    uid = event.sender_id
    if event.data == b"reg":
        states[uid] = {'step': 'phone'}
        await event.respond("Введите номер (+7...)")
    elif event.data == b"st":
        c = user_clients[uid]
        a = await c(functions.account.GetAuthorizationsRequest())
        await event.respond(f"Активных сессий: {len(a.authorizations)}")
    elif event.data == b"kick":
        c = user_clients[uid]
        res = await c(functions.account.GetAuthorizationsRequest())
        for a in res.authorizations:
            if not a.current: await c(functions.account.ResetAuthorizationRequest(hash=a.hash))
        await event.respond("💀 Очищено!")
    elif event.data == b"del":
        if uid in user_clients: 
            await user_clients[uid].disconnect()
            del user_clients[uid]
        if os.path.exists(f"vault/{uid}.txt"): os.remove(f"vault/{uid}.txt")
        await event.respond("🗑 Данные стерты.")

# ================= ВХОД И ШИФРОВАНИЕ =================

@bot.on(events.NewMessage)
async def login_logic(event):
    uid = event.sender_id
    if uid not in states or event.text.startswith('/'): return
    
    step = states[uid]['step']
    try:
        if step == 'phone':
            # Используем StringSession (в памяти), а не файл!
            client = TelegramClient(StringSession(), API_ID, API_HASH)
            await client.connect()
            sent = await client.send_code_request(event.text)
            states[uid] = {'step': 'code', 'phone': event.text, 'hash': sent.phone_code_hash, 'client': client}
            await event.respond("Код из ТГ:")
        
        elif step == 'code':
            d = states[uid]
            try:
                await d['client'].sign_in(d['phone'], event.text, phone_code_hash=d['hash'])
                
                # ШИФРУЕМ И СОХРАНЯЕМ
                session_str = d['client'].session.save()
                encrypted_session = encrypt_data(session_str, MASTER_KEY)
                with open(f"vault/{uid}.txt", "w") as f:
                    f.write(encrypted_session)
                
                user_clients[uid] = d['client']
                asyncio.create_task(run_guard(d['client'], uid))
                del states[uid]
                await event.respond("✅ Защита включена! Сессия зашифрована.")
            except errors.SessionPasswordNeededError:
                states[uid]['step'] = '2fa'
                await event.respond("Пароль 2FA:")
        
        elif step == '2fa':
            c = states[uid]['client']
            await c.sign_in(password=event.text)
            session_str = c.session.save()
            with open(f"vault/{uid}.txt", "w") as f:
                f.write(encrypt_data(session_str, MASTER_KEY))
            user_clients[uid] = c
            asyncio.create_task(run_guard(c, uid))
            del states[uid]
            await event.respond("✅ Успешно (2FA)!")

    except Exception as e:
        await event.respond(f"Ошибка: {e}")

# ================= ВОССТАНОВЛЕНИЕ =================

async def main():
    if os.path.exists('vault'):
        for f_name in os.listdir('vault'):
            try:
                uid = int(f_name.replace('.txt', ''))
                with open(f"vault/{f_name}", "r") as f:
                    encrypted_str = f.read()
                
                # Расшифровываем сессию обратно в память
                decrypted_str = decrypt_data(encrypted_str, MASTER_KEY)
                c = TelegramClient(StringSession(decrypted_str), API_ID, API_HASH)
                await c.connect()
                
                if await c.is_user_authorized():
                    user_clients[uid] = c
                    asyncio.create_task(run_guard(c, uid))
            except: pass
    await bot.run_until_disconnected()

if __name__ == '__main__':
    bot.loop.run_until_complete(main())
