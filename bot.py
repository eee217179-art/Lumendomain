import asyncio
import ipaddress
import logging
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime

import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dnslib import QTYPE, RCODE, RR, SOA, SRV, A, CNAME, NS
from dnslib.server import BaseResolver, DNSLogger, DNSServer
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
BASE_DOMAIN = os.environ["BASE_DOMAIN"].lower().strip(".")   # например: lumen.fun
SERVER_IP = os.environ["SERVER_IP"]                          # публичный IP VPS, где крутится бот
DNS_BIND = os.getenv("DNS_BIND", "0.0.0.0")                  # на Ubuntu лучше указать публичный IP
DNS_PORT = int(os.getenv("DNS_PORT", "53"))
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}
MAX_DOMAINS = int(os.getenv("MAX_DOMAINS_PER_USER", "3"))
DB_PATH = os.getenv("DB_PATH", "domains.db")

NS1, NS2 = f"ns1.{BASE_DOMAIN}", f"ns2.{BASE_DOMAIN}"
TTL = 300

RESERVED = {
    "www", "mail", "ftp", "smtp", "imap", "pop", "admin", "root", "api", "ns", "ns1", "ns2",
    "panel", "dashboard", "cpanel", "webmail", "support", "billing", "status", "dev", "test",
    "mc", "play", "minecraft",
}
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$")
HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

KINDS = {
    "mc": "⛏ Minecraft-сервер",
    "a": "🌐 Сайт (A-запись, IP)",
    "cname": "🔗 Сайт (CNAME, на другой хост)",
}

logging.basicConfig(level=logging.INFO)
router = Router()


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# ───────────────────────── DNS-сервер ─────────────────────────
def find_domain(label: str):
    with closing(sqlite3.connect(DB_PATH, timeout=5)) as db:
        return db.execute("SELECT kind, target, port FROM domains WHERE name=?", (label,)).fetchone()


class Resolver(BaseResolver):
    """Авторитативный резолвер только для BASE_DOMAIN. Записи берутся прямо из БД бота."""

    def resolve(self, request, handler):
        reply = request.reply()
        q = request.q
        qname = str(q.qname).rstrip(".").lower()
        qtype = q.qtype

        # только наша зона (иначе мы стали бы открытым резолвером)
        if qname != BASE_DOMAIN and not qname.endswith("." + BASE_DOMAIN):
            reply.header.rcode = RCODE.REFUSED
            return reply
        # ANY/AXFR запрещаем — защита от DNS-амплификации
        if qtype in (QTYPE.ANY, QTYPE.AXFR, QTYPE.IXFR):
            reply.header.rcode = RCODE.REFUSED
            return reply

        reply.header.aa = 1
        soa = RR(
            BASE_DOMAIN, QTYPE.SOA, ttl=60,
            rdata=SOA(NS1, f"hostmaster.{BASE_DOMAIN}", (int(time.time()), 3600, 600, 86400, 60)),
        )

        # сама зона и наши NS
        if qname in (BASE_DOMAIN, NS1, NS2):
            if qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=TTL))
            elif qtype == QTYPE.NS and qname == BASE_DOMAIN:
                for ns in (NS1, NS2):
                    reply.add_answer(RR(BASE_DOMAIN, QTYPE.NS, rdata=NS(ns), ttl=TTL))
                    reply.add_ar(RR(ns, QTYPE.A, rdata=A(SERVER_IP), ttl=TTL))
            elif qtype == QTYPE.SOA and qname == BASE_DOMAIN:
                reply.add_answer(soa)
            else:
                reply.add_auth(soa)
            return reply

        labels = qname[: -len(BASE_DOMAIN) - 1].split(".")

        # _minecraft._tcp.name.BASE → SRV
        if len(labels) == 3 and labels[0] == "_minecraft" and labels[1] == "_tcp":
            label = labels[2]
            row = find_domain(label)
            if not row:
                reply.header.rcode = RCODE.NXDOMAIN
                reply.add_auth(soa)
                return reply
            kind, target, port = row
            port = port or 25565
            if kind == "mc" and qtype == QTYPE.SRV and (port != 25565 or not is_ip(target)):
                fqdn = f"{label}.{BASE_DOMAIN}"
                srv_target = fqdn if is_ip(target) else target
                reply.add_answer(RR(qname, QTYPE.SRV, rdata=SRV(0, 5, port, srv_target), ttl=TTL))
                if is_ip(target):
                    reply.add_ar(RR(fqdn, QTYPE.A, rdata=A(target), ttl=TTL))
            else:
                reply.add_auth(soa)
            return reply

        # name.BASE → A / CNAME
        if len(labels) == 1:
            row = find_domain(labels[0])
            if not row:
                reply.header.rcode = RCODE.NXDOMAIN
                reply.add_auth(soa)
                return reply
            kind, target, _port = row
            if kind in ("a", "mc") and is_ip(target):
                if qtype == QTYPE.A:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(target), ttl=TTL))
                else:
                    reply.add_auth(soa)
            elif kind == "cname":
                reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(target), ttl=TTL))
            else:
                reply.add_auth(soa)
            return reply

        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_auth(soa)
        return reply


def start_dns():
    resolver = Resolver()
    logger = DNSLogger(log="error", prefix=False)
    for tcp in (False, True):
        DNSServer(resolver, port=DNS_PORT, address=DNS_BIND, tcp=tcp, logger=logger).start_thread()
    logging.info("DNS-сервер запущен на %s:%s (UDP+TCP)", DNS_BIND, DNS_PORT)


# ───────────────────────── База данных ─────────────────────────
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute(
            """CREATE TABLE IF NOT EXISTS domains(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                port INTEGER,
                created_at TEXT NOT NULL)"""
        )
        await db.execute("CREATE TABLE IF NOT EXISTS banned(user_id INTEGER PRIMARY KEY)")
        await db.execute("CREATE TABLE IF NOT EXISTS users(user_id INTEGER PRIMARY KEY)")
        await db.commit()


async def is_banned(uid: int) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM banned WHERE user_id=?", (uid,)) as c:
            return await c.fetchone() is not None


async def user_domains(uid: int):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, name, kind, target, port FROM domains WHERE user_id=? ORDER BY id", (uid,)
        ) as c:
            return await c.fetchall()


# ───────────────────────── Клавиатуры ─────────────────────────
def main_kb():
    kb = InlineKeyboardBuilder()
    kb.button(text="➕ Создать домен", callback_data="new")
    kb.button(text="📂 Мои домены", callback_data="my")
    kb.button(text="ℹ️ Помощь", callback_data="help")
    kb.adjust(1)
    return kb.as_markup()


def kinds_kb():
    kb = InlineKeyboardBuilder()
    for k, v in KINDS.items():
        kb.button(text=v, callback_data=f"kind:{k}")
    kb.button(text="⬅️ Назад", callback_data="menu")
    kb.adjust(1)
    return kb.as_markup()


def back_kb():
    kb = InlineKeyboardBuilder()
    kb.button(text="⬅️ В меню", callback_data="menu")
    return kb.as_markup()


class Create(StatesGroup):
    name = State()
    target = State()


def parse_target(kind: str, text: str):
    """Возвращает (host_or_ip, port, is_ip)."""
    text = text.strip().lower()
    port = None
    if kind == "mc" and ":" in text:
        text, p = text.rsplit(":", 1)
        if not p.isdigit() or not (1 <= int(p) <= 65535):
            raise ValueError("Порт должен быть числом от 1 до 65535.")
        port = int(p)
    if is_ip(text):
        ip = ipaddress.ip_address(text)
        if ip.version != 4:
            raise ValueError("Поддерживается только IPv4.")
        if not ip.is_global:
            raise ValueError("Нужен публичный IP-адрес (не локальный).")
        return text, port, True
    if not HOST_RE.match(text):
        raise ValueError("Это не похоже на IP или домен.")
    if text == BASE_DOMAIN or text.endswith("." + BASE_DOMAIN):
        raise ValueError("Нельзя указывать наш же домен как цель.")
    return text, port, False


# ───────────────────────── Хэндлеры ─────────────────────────
@router.message(CommandStart())
async def start(m: Message, state: FSMContext):
    await state.clear()
    if await is_banned(m.from_user.id):
        return await m.answer("⛔ Доступ закрыт.")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO users VALUES(?)", (m.from_user.id,))
        await db.commit()
    await m.answer(
        f"👋 Привет! Я создаю красивые домены вида <code>name.{BASE_DOMAIN}</code>\n"
        "для Minecraft-серверов, сайтов и не только.\n\nВыбери действие:",
        reply_markup=main_kb(),
    )


@router.callback_query(F.data == "menu")
async def menu(c: CallbackQuery, state: FSMContext):
    await state.clear()
    await c.message.edit_text("Главное меню:", reply_markup=main_kb())
    await c.answer()


@router.callback_query(F.data == "help")
async def help_cb(c: CallbackQuery):
    await c.message.edit_text(
        "<b>Как это работает</b>\n\n"
        f"⛏ <b>Minecraft</b> — игроки заходят по <code>name.{BASE_DOMAIN}</code> без порта "
        "(SRV-запись). Укажи IP или хост сервера, можно с портом: <code>1.2.3.4:25570</code>.\n"
        "🌐 <b>Сайт (A)</b> — домен ведёт на IP сервера.\n"
        "🔗 <b>Сайт (CNAME)</b> — домен ведёт на другой хост (GitHub Pages, Vercel и т.д.).\n\n"
        f"Лимит: {MAX_DOMAINS} домена(ов) на пользователя.",
        reply_markup=back_kb(),
    )
    await c.answer()


@router.callback_query(F.data == "new")
async def new(c: CallbackQuery):
    if await is_banned(c.from_user.id):
        return await c.answer("⛔ Доступ закрыт.", show_alert=True)
    if len(await user_domains(c.from_user.id)) >= MAX_DOMAINS:
        return await c.answer(f"Лимит {MAX_DOMAINS} доменов. Удали ненужный.", show_alert=True)
    await c.message.edit_text("Для чего нужен домен?", reply_markup=kinds_kb())
    await c.answer()


@router.callback_query(F.data.startswith("kind:"))
async def choose_kind(c: CallbackQuery, state: FSMContext):
    await state.update_data(kind=c.data.split(":")[1])
    await state.set_state(Create.name)
    await c.message.edit_text(
        "Придумай имя домена (3–32 символа: a-z, 0-9, дефис).\n"
        f"Например: <code>mycraft</code> → <code>mycraft.{BASE_DOMAIN}</code>",
        reply_markup=back_kb(),
    )
    await c.answer()


@router.message(Create.name)
async def got_name(m: Message, state: FSMContext):
    name = (m.text or "").strip().lower()
    if not NAME_RE.match(name) or "--" in name:
        return await m.answer("❌ Неверное имя. Только a-z, 0-9 и дефис, 3–32 символа.")
    if name in RESERVED:
        return await m.answer("❌ Это имя зарезервировано, выбери другое.")
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM domains WHERE name=?", (name,)) as cur:
            if await cur.fetchone():
                return await m.answer("❌ Этот домен уже занят. Попробуй другое имя.")

    await state.update_data(name=name)
    await state.set_state(Create.target)
    kind = (await state.get_data())["kind"]
    hint = {
        "mc": "IP или хост сервера, можно с портом: <code>1.2.3.4</code> или <code>1.2.3.4:25570</code>",
        "a": "IPv4-адрес сервера: <code>1.2.3.4</code>",
        "cname": "хост, куда вести домен: <code>user.github.io</code>",
    }[kind]
    await m.answer(f"✅ <code>{name}.{BASE_DOMAIN}</code> свободен!\n\nТеперь отправь {hint}")


@router.message(Create.target)
async def got_target(m: Message, state: FSMContext):
    data = await state.get_data()
    kind, name = data["kind"], data["name"]
    try:
        host, port, ip = parse_target(kind, m.text or "")
        if kind == "a" and not ip:
            raise ValueError("Для A-записи нужен IP. Для домена выбери CNAME.")
        if kind == "cname" and ip:
            raise ValueError("Для CNAME нужен хост, а не IP. Для IP выбери A-запись.")
    except ValueError as e:
        return await m.answer(f"❌ {e}")

    if len(await user_domains(m.from_user.id)) >= MAX_DOMAINS:
        await state.clear()
        return await m.answer("Лимит доменов исчерпан.", reply_markup=main_kb())

    if kind == "mc":
        port = port or 25565
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO domains(user_id,name,kind,target,port,created_at) VALUES(?,?,?,?,?,?)",
                (m.from_user.id, name, kind, host, port, datetime.utcnow().isoformat()),
            )
            await db.commit()
    except sqlite3.IntegrityError:
        await state.clear()
        return await m.answer("❌ Имя только что заняли, попробуй другое.", reply_markup=main_kb())
    await state.clear()
    await m.answer(
        f"🎉 Готово!\n\n<code>{name}.{BASE_DOMAIN}</code> → "
        f"<code>{host}{':' + str(port) if port else ''}</code>\n\n"
        "Запись работает сразу (кэш у провайдеров может держаться до 5 минут).",
        reply_markup=main_kb(),
    )


@router.callback_query(F.data == "my")
async def my(c: CallbackQuery):
    rows = await user_domains(c.from_user.id)
    if not rows:
        await c.message.edit_text("У тебя пока нет доменов.", reply_markup=back_kb())
        return await c.answer()
    kb = InlineKeyboardBuilder()
    text = "<b>Твои домены:</b>\n\n"
    for did, name, kind, target, port in rows:
        text += (f"{KINDS[kind].split(' ')[0]} <code>{name}.{BASE_DOMAIN}</code> → "
                 f"<code>{target}{':' + str(port) if port else ''}</code>\n")
        kb.button(text=f"🗑 {name}", callback_data=f"del:{did}")
    kb.button(text="⬅️ В меню", callback_data="menu")
    kb.adjust(1)
    await c.message.edit_text(text, reply_markup=kb.as_markup())
    await c.answer()


@router.callback_query(F.data.startswith("del:"))
async def delete_domain(c: CallbackQuery):
    did = int(c.data.split(":")[1])
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT user_id, name FROM domains WHERE id=?", (did,)) as cur:
            row = await cur.fetchone()
        if not row or (row[0] != c.from_user.id and c.from_user.id not in ADMIN_IDS):
            return await c.answer("Домен не найден.", show_alert=True)
        await db.execute("DELETE FROM domains WHERE id=?", (did,))
        await db.commit()
    await c.answer(f"Домен {row[1]} удалён")
    await my(c)


# ───────────────────────── Админка ─────────────────────────
@router.message(Command("stats"), F.from_user.id.in_(ADMIN_IDS))
async def stats(m: Message):
    async with aiosqlite.connect(DB_PATH) as db:
        u = (await (await db.execute("SELECT COUNT(*) FROM users")).fetchone())[0]
        d = (await (await db.execute("SELECT COUNT(*) FROM domains")).fetchone())[0]
    await m.answer(f"👥 Пользователей: {u}\n🌐 Доменов: {d}")


@router.message(Command("ban"), F.from_user.id.in_(ADMIN_IDS))
async def ban(m: Message):
    parts = (m.text or "").split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await m.answer("Использование: /ban <user_id>")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO banned VALUES(?)", (int(parts[1]),))
        await db.commit()
    await m.answer("Пользователь заблокирован.")


@router.message(Command("unban"), F.from_user.id.in_(ADMIN_IDS))
async def unban(m: Message):
    parts = (m.text or "").split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await m.answer("Использование: /unban <user_id>")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM banned WHERE user_id=?", (int(parts[1]),))
        await db.commit()
    await m.answer("Пользователь разблокирован.")


@router.message(Command("freedomain"), F.from_user.id.in_(ADMIN_IDS))
async def freedomain(m: Message):
    parts = (m.text or "").split()
    if len(parts) != 2:
        return await m.answer("Использование: /freedomain <name>")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("DELETE FROM domains WHERE name=?", (parts[1].lower(),))
        await db.commit()
    await m.answer("Домен удалён." if cur.rowcount else "Не найден.")


# ───────────────────────── Запуск ─────────────────────────
async def main():
    await init_db()
    start_dns()
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
