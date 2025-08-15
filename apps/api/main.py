# apps/api/main.py
import os
import re
from datetime import datetime, timedelta
from typing import Optional, List

from dotenv import load_dotenv
load_dotenv("env.txt")

import httpx
from uuid import uuid4
from cryptography.fernet import Fernet
from fastapi import FastAPI, Depends, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from sqlmodel import SQLModel, Field, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import bcrypt
from fastapi import UploadFile, File
from fastapi.staticfiles import StaticFiles
import pathlib
# =========================
# SETTINGS
# =========================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./altrina.db")
JWT_SECRET = os.getenv("JWT_SECRET", "dev")
JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")]

# Публичный базовый URL вебхука (ngrok / домен)
# Пример: https://xxxx-xx-xx-xx-xx.ngrok-free.app/v1/telegram/webhook
TELEGRAM_WEBHOOK_BASE = os.getenv("TELEGRAM_WEBHOOK_BASE", "")

# Стабильный ключ для шифрования токенов ботов (обязательно положи в .env)
FERNET_KEY = os.getenv("TELEGRAM_ENC_KEY")
if not FERNET_KEY:
    # В dev сгенерируем, но в prod ДОЛЖЕН быть задан (иначе после рестарта токены не расшифровать)
    FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

TG_BASE = "https://api.telegram.org"

# =========================
# DB
# =========================
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_session():
    async with SessionLocal() as s:
        yield s

# =========================
# APP
# =========================
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = pathlib.Path("./uploads")
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=False), name="static")

# =========================
# MODELS
# =========================
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: Optional[str] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = "Europe/Moscow"
    locale: Optional[str] = "ru"
    theme: Optional[str] = "light"  # light, dark, auto
    notifications_email: bool = True
    notifications_telegram: bool = True
    two_factor_enabled: bool = False
    last_login: Optional[datetime] = None
    login_count: int = 0
    provider: Optional[str] = None
    provider_user_id: Optional[str] = None
    password_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)

class Bot(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    bot_username: Optional[str] = None          # @handle без @
    bot_name: Optional[str] = None              # first_name из getMe
    secret_path_token: str = Field(index=True, unique=True)
    token_enc: str                               # зашифрованный токен
    ai_enabled: bool = True
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.now)

class BotFaq(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    bot_id: int = Field(index=True)
    question: str
    answer: str
    created_at: datetime = Field(default_factory=datetime.now)

class MessageLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    bot_id: int = Field(index=True)
    chat_id: Optional[int] = Field(default=None, index=True)
    direction: str = Field(default="in")  # 'in' | 'out'
    ok: Optional[bool] = None             # для 'out'
    text: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
class BotSettings(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    bot_id: int = Field(index=True, unique=True)
    greeting_text: Optional[str] = None
    fallback_text: Optional[str] = None
    ai_enabled: bool = True
    booking_enabled: bool = False
    timezone: Optional[str] = "Europe/Moscow"
    locale: Optional[str] = "ru"
    hours_json: Optional[str] = None
    quick_replies_json: Optional[str] = None
    commands_json: Optional[str] = None
    # Новые поля для полноценной настройки
    bot_description: Optional[str] = None
    bot_avatar_url: Optional[str] = None
    services_text: Optional[str] = None
    booking_text: Optional[str] = None
    faq_text: Optional[str] = None
    schedule_text: Optional[str] = None
    location_text: Optional[str] = None
    contact_phone: Optional[str] = None
    contact_email: Optional[str] = None
    business_address: Optional[str] = None

# =========================
# SCHEMAS
# =========================
class TokenOut(BaseModel):
    access_token: str

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class OAuthIn(BaseModel):
    provider: str
    provider_user_id: str
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None

class BotCreate(BaseModel):
    telegram_bot_token: str
    business_type: Optional[str] = None
    features: Optional[List[str]] = None

class BotPatch(BaseModel):
    bot_name: Optional[str] = None
    ai_enabled: Optional[bool] = None

class BotOut(BaseModel):
    id: int
    bot_username: Optional[str] = None
    bot_name: Optional[str] = None
    secret_path_token: str
    ai_enabled: bool
    active: bool
    created_at: datetime

class QAItem(BaseModel):
    question: str
    answer: str

class StatsOut(BaseModel):
    users_24h: int
    messages_today: int
    ai_success_24h: float
    recent: list[dict]

class AnalyticsOut(BaseModel):
    overview: dict
    engagement: dict
    performance: dict
    trends: dict
    user_behavior: dict
    conversion_funnel: dict

class BotSettingsPatch(BaseModel):
    greeting_text: Optional[str] = None
    fallback_text: Optional[str] = None
    ai_enabled: Optional[bool] = None
    booking_enabled: Optional[bool] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    hours_json: Optional[str] = None
    quick_replies_json: Optional[str] = None
    commands_json: Optional[str] = None
    # Новые поля
    bot_description: Optional[str] = None
    bot_avatar_url: Optional[str] = None
    services_text: Optional[str] = None
    booking_text: Optional[str] = None
    faq_text: Optional[str] = None
    schedule_text: Optional[str] = None
    location_text: Optional[str] = None
    contact_phone: Optional[str] = None
    contact_email: Optional[str] = None
    business_address: Optional[str] = None

class BotDetailOut(BaseModel):
    bot: BotOut
    settings: BotSettingsPatch
    webhook_url: str
    webhook_info: Optional[dict] = None

# =========================
# AUTH HELPERS
# =========================
def create_access_token(payload: dict, exp_minutes: int = 60*24*7):
    to_encode = payload.copy()
    to_encode["exp"] = datetime.now() + timedelta(minutes=exp_minutes)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

bearer = HTTPBearer(auto_error=False)

async def current_user(
    creds: HTTPAuthorizationCredentials = Security(bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    if not creds:
        raise HTTPException(401, "Нет токена")
    try:
        data = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        uid = int(data.get("sub"))
    except JWTError:
        raise HTTPException(401, "Недействительный токен")
    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "Пользователь не найден")
    return user

class UserPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    short_description: Optional[str] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    theme: Optional[str] = None
    notifications_email: Optional[bool] = None
    notifications_telegram: Optional[bool] = None

class AccountStatsOut(BaseModel):
    total_bots: int
    total_messages: int
    account_age_days: int
    last_login: Optional[str] = None
    login_count: int
    storage_used: str
    api_calls_today: int

class SecuritySettingsOut(BaseModel):
    two_factor_enabled: bool
    last_password_change: Optional[str] = None
    active_sessions: int
    recent_logins: list[dict]

class NotificationSettingsOut(BaseModel):
    email_enabled: bool
    telegram_enabled: bool
    email_types: list[str]
    telegram_types: list[str]

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

@app.patch("/users/me")
async def update_me(body: UserPatch, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    if body.name is not None:
        user.name = body.name
    if body.description is not None:
        user.description = body.description
    if body.short_description is not None:
        user.short_description = body.short_description
    if body.timezone is not None:
        user.timezone = body.timezone
    if body.locale is not None:
        user.locale = body.locale
    if body.theme is not None:
        user.theme = body.theme
    if body.notifications_email is not None:
        user.notifications_email = body.notifications_email
    if body.notifications_telegram is not None:
        user.notifications_telegram = body.notifications_telegram
    session.add(user)
    await session.commit()
    return {"ok": True}

@app.post("/auth/change-password")
async def change_password(body: ChangePasswordIn, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    if not user.password_hash or not bcrypt.verify(body.current_password, user.password_hash):
        raise HTTPException(400, "Текущий пароль неверен")
    if len(body.new_password) < 6:
        raise HTTPException(400, "Пароль слишком короткий")
    user.password_hash = bcrypt.hash(body.new_password)
    session.add(user)
    await session.commit()
    return {"ok": True}

@app.post("/users/me/avatar")
async def upload_avatar(file: UploadFile = File(...), user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    ext = (file.filename or "png").split(".")[-1].lower()
    if ext not in {"png", "jpg", "jpeg", "webp"}:
        raise HTTPException(400, "Поддерживаются png/jpg/webp")
    user_dir = STATIC_DIR / "avatars"
    user_dir.mkdir(parents=True, exist_ok=True)
    path = user_dir / f"{user.id}.webp"  # нормализуем формат
    data = await file.read()
    path.write_bytes(data)
    # публичный URL
    url = f"/static/avatars/{user.id}.webp"
    user.avatar_url = url
    session.add(user); await session.commit()
    return {"url": url}

@app.post("/users/me/setMyName")
async def set_my_name(body: dict, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(400, "Имя не может быть пустым")
    user.name = name
    session.add(user)
    await session.commit()
    return {"ok": True, "name": user.name}

@app.post("/users/me/setMyDescription")
async def set_my_description(body: dict, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    description = body.get("description", "").strip()
    user.description = description
    session.add(user)
    await session.commit()
    return {"ok": True, "description": user.description}

@app.post("/users/me/setMyShortDescription")
async def set_my_short_description(body: dict, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    short_description = body.get("short_description", "").strip()
    user.short_description = short_description
    session.add(user)
    await session.commit()
    return {"ok": True, "short_description": user.short_description}

@app.get("/users/me/stats", response_model=AccountStatsOut)
async def get_account_stats(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    # Статистика ботов
    bots = (await session.execute(select(Bot).where(Bot.user_id == user.id))).scalars().all()
    total_bots = len(bots)
    
    # Статистика сообщений
    total_messages = 0
    api_calls_today = 0
    today = start_of_today()
    
    for bot in bots:
        messages = (await session.execute(select(MessageLog).where(MessageLog.bot_id == bot.id))).scalars().all()
        total_messages += len(messages)
        
        today_messages = (await session.execute(
            select(MessageLog).where(MessageLog.bot_id == bot.id, MessageLog.created_at >= today)
        )).scalars().all()
        api_calls_today += len(today_messages)
    
    # Возраст аккаунта
    account_age = datetime.now() - user.created_at
    account_age_days = account_age.days
    
    # Примерное использование хранилища
    storage_used = f"{(total_messages * 0.5 + total_bots * 10):.1f} MB"
    
    return AccountStatsOut(
        total_bots=total_bots,
        total_messages=total_messages,
        account_age_days=account_age_days,
        last_login=user.last_login.isoformat() if user.last_login else None,
        login_count=user.login_count,
        storage_used=storage_used,
        api_calls_today=api_calls_today
    )

@app.get("/users/me/security", response_model=SecuritySettingsOut)
async def get_security_settings(user: User = Depends(current_user)):
    # Примерные данные для демонстрации
    recent_logins = [
        {
            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
            "ip": "192.168.1.100",
            "location": "Москва, Россия",
            "device": "Chrome на MacBook"
        },
        {
            "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
            "ip": "192.168.1.100",
            "location": "Москва, Россия", 
            "device": "Safari на iPhone"
        }
    ]
    
    return SecuritySettingsOut(
        two_factor_enabled=user.two_factor_enabled,
        last_password_change=(datetime.now() - timedelta(days=30)).isoformat(),
        active_sessions=2,
        recent_logins=recent_logins
    )

@app.get("/users/me/notifications", response_model=NotificationSettingsOut)
async def get_notification_settings(user: User = Depends(current_user)):
    return NotificationSettingsOut(
        email_enabled=user.notifications_email,
        telegram_enabled=user.notifications_telegram,
        email_types=["new_messages", "bot_errors", "security_alerts", "weekly_reports"],
        telegram_types=["urgent_alerts", "bot_down", "security_events"]
    )

@app.post("/users/me/enable-2fa")
async def enable_two_factor(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    user.two_factor_enabled = True
    session.add(user)
    await session.commit()
    return {"ok": True, "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="}

@app.post("/users/me/disable-2fa")
async def disable_two_factor(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    user.two_factor_enabled = False
    session.add(user)
    await session.commit()
    return {"ok": True}

@app.post("/users/me/export-data")
async def export_user_data(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    # Экспорт данных пользователя
    bots = (await session.execute(select(Bot).where(Bot.user_id == user.id))).scalars().all()
    
    export_data = {
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "created_at": user.created_at.isoformat()
        },
        "bots": [
            {
                "id": bot.id,
                "username": bot.bot_username,
                "name": bot.bot_name,
                "created_at": bot.created_at.isoformat()
            } for bot in bots
        ],
        "export_date": datetime.now().isoformat()
    }
    
    return {"download_url": "/static/exports/user_data.json", "data": export_data}

@app.delete("/users/me")
async def delete_me(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    # каскадно удалим ботов и их данные (простая версия)
    bots = (await session.execute(select(Bot).where(Bot.user_id == user.id))).scalars().all()
    for b in bots:
        await session.delete(b)
    await session.delete(user)
    await session.commit()
    return {"ok": True}
# =========================
# UTILS / LOGGING
# =========================
async def log_event(session: AsyncSession, *, bot_id: int, chat_id: Optional[int], direction: str, text: Optional[str], ok: Optional[bool] = None):
    session.add(MessageLog(bot_id=bot_id, chat_id=chat_id, direction=direction, text=text, ok=ok))
    await session.commit()

def start_of_today() -> datetime:
    now = datetime.now()
    return datetime(year=now.year, month=now.month, day=now.day)

# =========================
# TELEGRAM HELPERS
# =========================
def encrypt_token(token: str) -> str:
    return fernet.encrypt(token.encode()).decode()

def decrypt_token(token_enc: str) -> str:
    return fernet.decrypt(token_enc.encode()).decode()

async def tg_call(token: str, method: str, payload: dict):
    url = f"{TG_BASE}/bot{token}/{method}"
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise HTTPException(400, f"Telegram error: {data}")
    return data["result"]

async def tg_get_me(token: str):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{TG_BASE}/bot{token}/getMe")
            r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            error_description = data.get("description", "Unknown error")
            raise HTTPException(400, f"Неверный токен бота: {error_description}")
        return data["result"]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise HTTPException(400, "Неверный токен бота (Unauthorized)")
        elif e.response.status_code == 404:
            raise HTTPException(400, "Неверный токен бота (Not Found)")
        else:
            raise HTTPException(400, f"Ошибка Telegram API: {e.response.status_code}")
    except httpx.RequestError as e:
        raise HTTPException(500, f"Ошибка подключения к Telegram API: {str(e)}")
    except Exception as e:
        raise HTTPException(500, f"Неожиданная ошибка при проверке токена: {str(e)}")

async def tg_set_webhook(token: str, webhook_url: str):
    return await tg_call(token, "setWebhook", {"url": webhook_url})

async def tg_send_message(token: str, chat_id: int, text: str):
    return await tg_call(token, "sendMessage", {"chat_id": chat_id, "text": text})

async def tg_get_webhook_info(token: str):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{TG_BASE}/bot{token}/getWebhookInfo")
            r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            return None
        return data["result"]
    except Exception as e:
        print(f"Error getting webhook info: {e}")
        return None
# =========================
# STARTUP
# =========================


# =========================
# TELEGRAM DEBUG ROUTES
# =========================
@app.post("/telegram/check-token")
async def check_telegram_token(body: dict):
    """Проверка токена Telegram бота без создания бота"""
    token = body.get("token", "").strip()
    if not token:
        raise HTTPException(400, "Токен не указан")
    
    try:
        me = await tg_get_me(token)
        return {
            "valid": True,
            "bot_info": me,
            "username": me.get("username"),
            "first_name": me.get("first_name")
        }
    except HTTPException as e:
        return {
            "valid": False,
            "error": e.detail
        }
    except Exception as e:
        return {
            "valid": False,
            "error": f"Неожиданная ошибка: {str(e)}"
        }

# =========================
# AUTH ROUTES
# =========================
@app.post("/auth/register", response_model=TokenOut)
async def register(body: RegisterIn, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == body.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Пользователь уже существует")
    user = User(
        email=body.email,
        name=body.name,
        provider="email",
        password_hash=bcrypt.hash(body.password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return TokenOut(access_token=token)

@app.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not user.password_hash or not bcrypt.verify(body.password, user.password_hash):
        raise HTTPException(401, "Неверная почта или пароль")
    
    # Обновляем статистику входов
    user.last_login = datetime.now()
    user.login_count += 1
    session.add(user)
    await session.commit()
    
    token = create_access_token({"sub": str(user.id)})
    return TokenOut(access_token=token)

@app.post("/auth/oauth", response_model=TokenOut)
async def oauth_login(body: OAuthIn, session: AsyncSession = Depends(get_session)):
    q = select(User).where(User.provider == body.provider, User.provider_user_id == body.provider_user_id)
    result = await session.execute(q)
    user = result.scalar_one_or_none()
    if not user and body.email:
        result = await session.execute(select(User).where(User.email == body.email))
        user = result.scalar_one_or_none()
    if user:
        user.provider = body.provider
        user.provider_user_id = user.provider_user_id or body.provider_user_id
        if body.name and not user.name: user.name = body.name
        if body.avatar_url and not user.avatar_url: user.avatar_url = body.avatar_url
        await session.commit()
    else:
        user = User(
            email=body.email or f"{body.provider_user_id}@{body.provider}.local",
            name=body.name,
            avatar_url=body.avatar_url,
            provider=body.provider,
            provider_user_id=body.provider_user_id,
        )
        session.add(user); await session.commit(); await session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return TokenOut(access_token=token)

@app.get("/auth/me")
async def me(user: User = Depends(current_user)):
    return {
        "id": user.id, 
        "email": user.email, 
        "name": user.name,
        "description": user.description,
        "short_description": user.short_description,
        "avatar_url": user.avatar_url,
        "timezone": user.timezone,
        "locale": user.locale,
        "theme": user.theme,
        "notifications_email": user.notifications_email,
        "notifications_telegram": user.notifications_telegram,
        "two_factor_enabled": user.two_factor_enabled,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "login_count": user.login_count,
        "created_at": user.created_at.isoformat()
    }

# =========================
# BOTS ROUTES
# =========================
@app.post("/bots", response_model=BotOut)
async def create_bot(
    body: BotCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        token = body.telegram_bot_token.strip()
        if not re.match(r"^\d+:[A-Za-z0-9_-]{10,}$", token):
            raise HTTPException(400, "Похоже, это не Telegram Bot Token")

        # Проверяем токен через Telegram API
        try:
            me = await tg_get_me(token)
            username = me.get("username")
            first_name = me.get("first_name")
        except HTTPException as e:
            if e.status_code == 400:
                raise HTTPException(400, "Неверный токен бота. Проверьте правильность токена.")
            else:
                raise HTTPException(500, f"Ошибка при проверке токена: {e.detail}")
        except Exception as e:
            raise HTTPException(500, f"Ошибка при подключении к Telegram API: {str(e)}")

        # Проверяем, не существует ли уже бот с таким username в системе
        existing_bot = (await session.execute(
            select(Bot).where(Bot.bot_username == username)
        )).scalar_one_or_none()
        
        if existing_bot:
            raise HTTPException(400, f"Бот @{username} уже подключен к системе. Каждый бот может быть подключен только один раз.")

        secret = str(uuid4())
        
        # Настраиваем вебхук только если TELEGRAM_WEBHOOK_BASE доступен
        if TELEGRAM_WEBHOOK_BASE:
            webhook_url = f"{TELEGRAM_WEBHOOK_BASE.rstrip('/')}/v1/telegram/webhook/{secret}"
            try:
                await tg_set_webhook(token, webhook_url)
            except Exception as e:
                print(f"Warning: Failed to set webhook: {e}")
                # Не прерываем создание бота, просто логируем ошибку

        bot = Bot(
            user_id=user.id,
            bot_username=username,
            bot_name=first_name,
            secret_path_token=secret,
            token_enc=encrypt_token(token),
            ai_enabled=True,
            active=True,
        )
        session.add(bot)
        await session.commit()
        await session.refresh(bot)
        
        # Создаем настройки бота с дефолтными значениями
        default_settings = get_default_bot_settings(body.business_type or "other", body.features or [])
        booking_enabled = body.features and "booking" in body.features
        
        settings = BotSettings(
            bot_id=bot.id,
            ai_enabled=True,
            booking_enabled=booking_enabled,
            greeting_text=default_settings.get("greeting_text"),
            fallback_text=default_settings.get("fallback_text"),
            services_text=default_settings.get("services_text"),
            booking_text=default_settings.get("booking_text"),
            faq_text=default_settings.get("faq_text"),
            schedule_text=default_settings.get("schedule_text"),
            location_text=default_settings.get("location_text"),
            contact_phone=default_settings.get("contact_phone"),
            contact_email=default_settings.get("contact_email"),
            business_address=default_settings.get("business_address"),
            bot_description=default_settings.get("bot_description")
        )
        session.add(settings)
        
        await session.commit()
        
        # Настраиваем команды бота в зависимости от выбранных функций
        if body.features:
            try:
                commands = get_bot_commands(body.features)
                await tg_set_commands(token, commands)
            except Exception as e:
                # Логируем ошибку, но не прерываем создание бота
                print(f"Warning: Failed to set bot commands: {e}")
        
        return BotOut(
            id=bot.id,
            bot_username=bot.bot_username,
            bot_name=bot.bot_name,
            secret_path_token=bot.secret_path_token,
            ai_enabled=bot.ai_enabled,
            active=bot.active,
            created_at=bot.created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in create_bot: {e}")
        raise HTTPException(500, f"Внутренняя ошибка сервера: {str(e)}")
@app.get("/bots/{bot_id}/detail", response_model=BotDetailOut)
async def bot_detail(bot_id: int, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    settings = (await session.execute(select(BotSettings).where(BotSettings.bot_id == bot.id))).scalar_one_or_none()
    if not settings:
        settings = BotSettings(bot_id=bot.id); session.add(settings); await session.commit(); await session.refresh(settings)

    token = decrypt_token(bot.token_enc)
    webhook_url = f"{TELEGRAM_WEBHOOK_BASE.rstrip('/')}/v1/telegram/webhook/{bot.secret_path_token}" if TELEGRAM_WEBHOOK_BASE else ""
    webhook_info = await tg_get_webhook_info(token)

    return BotDetailOut(
        bot=BotOut(
            id=bot.id, bot_username=bot.bot_username, bot_name=bot.bot_name,
            secret_path_token=bot.secret_path_token, ai_enabled=bot.ai_enabled,
            active=bot.active, created_at=bot.created_at
        ),
        settings=BotSettingsPatch(
            greeting_text=settings.greeting_text,
            fallback_text=settings.fallback_text,
            ai_enabled=settings.ai_enabled,
            booking_enabled=settings.booking_enabled,
            timezone=settings.timezone,
            locale=settings.locale,
            hours_json=settings.hours_json,
            quick_replies_json=settings.quick_replies_json,
            commands_json=settings.commands_json,
            bot_description=settings.bot_description,
            bot_avatar_url=settings.bot_avatar_url,
            services_text=settings.services_text,
            booking_text=settings.booking_text,
            faq_text=settings.faq_text,
            schedule_text=settings.schedule_text,
            location_text=settings.location_text,
            contact_phone=settings.contact_phone,
            contact_email=settings.contact_email,
            business_address=settings.business_address,
        ),
        webhook_url=webhook_url,
        webhook_info=webhook_info,
    )

@app.patch("/bots/{bot_id}/settings", response_model=BotSettingsPatch)
async def patch_settings(bot_id: int, body: BotSettingsPatch, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    settings = (await session.execute(select(BotSettings).where(BotSettings.bot_id == bot.id))).scalar_one_or_none()
    if not settings:
        settings = BotSettings(bot_id=bot.id); session.add(settings); await session.commit(); await session.refresh(settings)

    for k, v in body.dict(exclude_unset=True).items():
        setattr(settings, k, v)
        if k == "ai_enabled":  # синхронизируем флаг на Bot
            bot.ai_enabled = bool(v)
    session.add_all([settings, bot])
    await session.commit(); await session.refresh(settings)

    return BotSettingsPatch(
        greeting_text=settings.greeting_text,
        fallback_text=settings.fallback_text,
        ai_enabled=settings.ai_enabled,
        booking_enabled=settings.booking_enabled,
        timezone=settings.timezone,
        locale=settings.locale,
        hours_json=settings.hours_json,
        quick_replies_json=settings.quick_replies_json,
        commands_json=settings.commands_json,
        bot_description=settings.bot_description,
        bot_avatar_url=settings.bot_avatar_url,
        services_text=settings.services_text,
        booking_text=settings.booking_text,
        faq_text=settings.faq_text,
        schedule_text=settings.schedule_text,
        location_text=settings.location_text,
        contact_phone=settings.contact_phone,
        contact_email=settings.contact_email,
        business_address=settings.business_address,
    )

@app.post("/bots/{bot_id}/rotate-secret")
async def rotate_secret(bot_id: int, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    if not TELEGRAM_WEBHOOK_BASE:
        raise HTTPException(500, "TELEGRAM_WEBHOOK_BASE не настроен")
    from uuid import uuid4
    bot.secret_path_token = str(uuid4())
    token = decrypt_token(bot.token_enc)
    webhook_url = f"{TELEGRAM_WEBHOOK_BASE.rstrip('/')}/v1/telegram/webhook/{bot.secret_path_token}"
    await tg_set_webhook(token, webhook_url)
    session.add(bot); await session.commit()
    return {"secret_path_token": bot.secret_path_token, "webhook_url": webhook_url}

@app.get("/bots/{bot_id}/logs", response_model=list[dict])
async def bot_logs(bot_id: int, limit: int = 25, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    q_recent = select(MessageLog).where(MessageLog.bot_id == bot.id).order_by(MessageLog.created_at.desc()).limit(limit)
    recent_logs = (await session.execute(q_recent)).scalars().all()
    return [{"id": lg.id, "dir": lg.direction, "text": lg.text, "ts": lg.created_at.isoformat()} for lg in recent_logs]

@app.post("/bots/{bot_id}/test-message")
async def test_message(bot_id: int, body: dict, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    chat_id = int(body.get("chat_id", 0))
    text = str(body.get("text") or "").strip()
    if not chat_id or not text:
        raise HTTPException(400, "chat_id и text обязательны")
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    token = decrypt_token(bot.token_enc)
    await tg_send_message(token, chat_id, text)
    await log_event(session, bot_id=bot.id, chat_id=chat_id, direction="out", text=text, ok=True)
    return {"ok": True}
@app.get("/bots", response_model=List[BotOut])
async def list_bots(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Bot).where(Bot.user_id == user.id))
    bots = result.scalars().all()
    return [
        BotOut(
            id=b.id,
            bot_username=b.bot_username,
            bot_name=b.bot_name,
            secret_path_token=b.secret_path_token,
            ai_enabled=b.ai_enabled,
            active=b.active,
            created_at=b.created_at,
        )
        for b in bots
    ]

@app.patch("/bots/{bot_id}", response_model=BotOut)
async def patch_bot(
    bot_id: int,
    body: BotPatch,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))
    bot = result.scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")
    if body.bot_name is not None:
        bot.bot_name = body.bot_name
    if body.ai_enabled is not None:
        bot.ai_enabled = body.ai_enabled
    await session.commit()
    await session.refresh(bot)
    return BotOut(
        id=bot.id,
        bot_username=bot.bot_username,
        bot_name=bot.bot_name,
        secret_path_token=bot.secret_path_token,
        ai_enabled=bot.ai_enabled,
        active=bot.active,
        created_at=bot.created_at,
    )

@app.post("/bots/{bot_id}/knowledge")
async def upload_knowledge(
    bot_id: int,
    items: List[QAItem],
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))
    bot = result.scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")

    for it in items:
        q = (it.question or "").strip()
        if q:
            session.add(BotFaq(bot_id=bot.id, question=q, answer=(it.answer or "").strip()))
    await session.commit()
    return {"ok": True, "count": len(items)}

@app.get("/bots/{bot_id}/stats", response_model=StatsOut)
async def bot_stats(bot_id: int, user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))
    bot = result.scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")

    today = start_of_today()
    since_24h = datetime.now() - timedelta(hours=24)

    # Сообщений сегодня (входящих)
    q_today = select(MessageLog).where(
        MessageLog.bot_id == bot.id,
        MessageLog.direction == "in",
        MessageLog.created_at >= today,
    )
    messages_today = len((await session.execute(q_today)).scalars().all())

    # Уникальные пользователи за 24ч
    q_24 = select(MessageLog.chat_id).where(
        MessageLog.bot_id == bot.id,
        MessageLog.created_at >= since_24h,
        MessageLog.chat_id.isnot(None),
    )
    chat_ids = [row[0] if isinstance(row, tuple) else row for row in (await session.execute(q_24)).all()]
    users_24h = len(set(chat_ids))

    # Успешные исходящие за 24ч
    q_out = select(MessageLog.ok).where(
        MessageLog.bot_id == bot.id,
        MessageLog.direction == "out",
        MessageLog.created_at >= since_24h,
    )
    outs = [row[0] if isinstance(row, tuple) else row for row in (await session.execute(q_out)).all()]
    sent = len(outs)
    ok = len([x for x in outs if x is True])
    ai_success_24h = float(ok) / sent * 100 if sent else 0.0

    # Последние 10 событий
    q_recent = select(MessageLog).where(MessageLog.bot_id == bot.id).order_by(MessageLog.created_at.desc()).limit(10)
    recent_logs = (await session.execute(q_recent)).scalars().all()
    recent = [{
        "id": lg.id,
        "dir": lg.direction,
        "text": lg.text,
        "ts": lg.created_at.isoformat(),
    } for lg in recent_logs]

    return StatsOut(
        users_24h=users_24h,
        messages_today=messages_today,
        ai_success_24h=round(ai_success_24h, 1),
        recent=recent,
    )

@app.get("/bots/{bot_id}/analytics", response_model=AnalyticsOut)
async def bot_analytics(bot_id: int, period: str = "7d", user: User = Depends(current_user), session: AsyncSession = Depends(get_session)):
    bot = (await session.execute(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Бот не найден")

    # Определяем период
    if period == "24h":
        start_date = datetime.now() - timedelta(hours=24)
    elif period == "7d":
        start_date = datetime.now() - timedelta(days=7)
    elif period == "30d":
        start_date = datetime.now() - timedelta(days=30)
    else:
        start_date = datetime.now() - timedelta(days=7)

    # Получаем все сообщения за период
    q_messages = select(MessageLog).where(
        MessageLog.bot_id == bot.id,
        MessageLog.created_at >= start_date
    ).order_by(MessageLog.created_at.desc())
    messages = (await session.execute(q_messages)).scalars().all()

    # Обзорные метрики
    total_messages = len(messages)
    incoming_messages = len([m for m in messages if m.direction == "in"])
    outgoing_messages = len([m for m in messages if m.direction == "out"])
    unique_users = len(set(m.chat_id for m in messages if m.chat_id))
    
    # Успешность ответов
    successful_responses = len([m for m in messages if m.direction == "out" and m.ok == True])
    failed_responses = len([m for m in messages if m.direction == "out" and m.ok == False])
    response_rate = (successful_responses / outgoing_messages * 100) if outgoing_messages > 0 else 0

    # Средний отклик
    response_times = []
    user_sessions = {}
    for msg in messages:
        if msg.chat_id:
            if msg.chat_id not in user_sessions:
                user_sessions[msg.chat_id] = []
            user_sessions[msg.chat_id].append(msg)
    
    # Вычисляем время ответа
    for chat_id, msgs in user_sessions.items():
        msgs.sort(key=lambda x: x.created_at)
        for i in range(len(msgs) - 1):
            if msgs[i].direction == "in" and msgs[i + 1].direction == "out":
                time_diff = (msgs[i + 1].created_at - msgs[i].created_at).total_seconds() / 60  # в минутах
                if time_diff < 60:  # только если ответ в течение часа
                    response_times.append(time_diff)
    
    avg_response_time = sum(response_times) / len(response_times) if response_times else 0

    # Анализ по дням
    daily_stats = {}
    for msg in messages:
        day = msg.created_at.strftime("%Y-%m-%d")
        if day not in daily_stats:
            daily_stats[day] = {"incoming": 0, "outgoing": 0, "users": set()}
        if msg.direction == "in":
            daily_stats[day]["incoming"] += 1
        else:
            daily_stats[day]["outgoing"] += 1
        if msg.chat_id:
            daily_stats[day]["users"].add(msg.chat_id)

    # Конвертируем в список для графиков
    daily_trends = []
    for day in sorted(daily_stats.keys()):
        daily_trends.append({
            "date": day,
            "incoming": daily_stats[day]["incoming"],
            "outgoing": daily_stats[day]["outgoing"],
            "unique_users": len(daily_stats[day]["users"])
        })

    # Анализ по часам (только для последних 24ч)
    hourly_stats = {}
    recent_24h = [m for m in messages if m.created_at >= datetime.now() - timedelta(hours=24)]
    for msg in recent_24h:
        hour = msg.created_at.hour
        if hour not in hourly_stats:
            hourly_stats[hour] = 0
        hourly_stats[hour] += 1

    hourly_distribution = [{"hour": h, "messages": hourly_stats.get(h, 0)} for h in range(24)]

    # Популярные фразы/команды
    incoming_texts = [m.text for m in messages if m.direction == "in" and m.text]
    command_stats = {}
    for text in incoming_texts:
        if text and text.startswith('/'):
            cmd = text.split()[0].lower()
            command_stats[cmd] = command_stats.get(cmd, 0) + 1

    top_commands = sorted(command_stats.items(), key=lambda x: x[1], reverse=True)[:5]

    # Воронка конверсий (примерная)
    total_visitors = unique_users
    engaged_users = len([chat_id for chat_id, msgs in user_sessions.items() if len(msgs) > 2])
    converted_users = len([chat_id for chat_id, msgs in user_sessions.items() if 
                          any("запис" in (m.text or "").lower() or "booking" in (m.text or "").lower() for m in msgs)])

    return AnalyticsOut(
        overview={
            "total_messages": total_messages,
            "incoming_messages": incoming_messages,
            "outgoing_messages": outgoing_messages,
            "unique_users": unique_users,
            "response_rate": round(response_rate, 1),
            "avg_response_time": round(avg_response_time, 1),
            "period": period
        },
        engagement={
            "daily_trends": daily_trends,
            "hourly_distribution": hourly_distribution,
            "most_active_hour": max(hourly_stats.items(), key=lambda x: x[1])[0] if hourly_stats else 0,
            "peak_activity": max(hourly_stats.values()) if hourly_stats else 0
        },
        performance={
            "successful_responses": successful_responses,
            "failed_responses": failed_responses,
            "response_rate": round(response_rate, 1),
            "avg_response_time": round(avg_response_time, 1),
            "response_time_distribution": {
                "under_1min": len([t for t in response_times if t < 1]),
                "1_5min": len([t for t in response_times if 1 <= t < 5]),
                "5_30min": len([t for t in response_times if 5 <= t < 30]),
                "over_30min": len([t for t in response_times if t >= 30])
            }
        },
        trends={
            "messages_growth": calculate_growth(daily_trends, "incoming"),
            "users_growth": calculate_growth(daily_trends, "unique_users"),
            "engagement_trend": calculate_engagement_trend(user_sessions),
            "top_commands": [{"command": cmd, "count": count} for cmd, count in top_commands]
        },
        user_behavior={
            "avg_messages_per_user": round(incoming_messages / unique_users, 1) if unique_users > 0 else 0,
            "returning_users": len([chat_id for chat_id, msgs in user_sessions.items() if 
                                  len(set(m.created_at.date() for m in msgs)) > 1]),
            "session_duration": calculate_avg_session_duration(user_sessions),
            "user_segments": {
                "new": len([chat_id for chat_id, msgs in user_sessions.items() if len(msgs) == 1]),
                "active": len([chat_id for chat_id, msgs in user_sessions.items() if 2 <= len(msgs) <= 10]),
                "power": len([chat_id for chat_id, msgs in user_sessions.items() if len(msgs) > 10])
            }
        },
        conversion_funnel={
            "visitors": total_visitors,
            "engaged": engaged_users,
            "converted": converted_users,
            "engagement_rate": round(engaged_users / total_visitors * 100, 1) if total_visitors > 0 else 0,
            "conversion_rate": round(converted_users / total_visitors * 100, 1) if total_visitors > 0 else 0
        }
    )

def calculate_growth(daily_trends: list, metric: str):
    """Вычисляет рост метрики за период"""
    if len(daily_trends) < 2:
        return 0
    
    recent_period = daily_trends[-3:] if len(daily_trends) >= 3 else daily_trends[-1:]
    previous_period = daily_trends[-6:-3] if len(daily_trends) >= 6 else daily_trends[:-3] if len(daily_trends) > 3 else []
    
    if not previous_period:
        return 0
    
    recent_avg = sum(day[metric] for day in recent_period) / len(recent_period)
    previous_avg = sum(day[metric] for day in previous_period) / len(previous_period)
    
    if previous_avg == 0:
        return 100 if recent_avg > 0 else 0
    
    return round((recent_avg - previous_avg) / previous_avg * 100, 1)

def calculate_engagement_trend(user_sessions: dict):
    """Вычисляет тренд вовлеченности пользователей"""
    if not user_sessions:
        return 0
    
    # Средняя активность на пользователя
    avg_messages = sum(len(msgs) for msgs in user_sessions.values()) / len(user_sessions)
    
    # Простая метрика: больше 3 сообщений = вовлеченный пользователь
    engaged = len([msgs for msgs in user_sessions.values() if len(msgs) > 3])
    engagement_rate = engaged / len(user_sessions) * 100 if user_sessions else 0
    
    return round(engagement_rate, 1)

def calculate_avg_session_duration(user_sessions: dict):
    """Вычисляет среднюю длительность сессии в минутах"""
    durations = []
    
    for msgs in user_sessions.values():
        if len(msgs) > 1:
            msgs_sorted = sorted(msgs, key=lambda x: x.created_at)
            duration = (msgs_sorted[-1].created_at - msgs_sorted[0].created_at).total_seconds() / 60
            if duration < 1440:  # меньше 24 часов
                durations.append(duration)
    
    return round(sum(durations) / len(durations), 1) if durations else 0

# =========================
# TELEGRAM WEBHOOK
# =========================
@app.post("/v1/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request, session: AsyncSession = Depends(get_session)):
    bot: Bot = (await session.execute(select(Bot).where(Bot.secret_path_token == secret, Bot.active == True))).scalar_one_or_none()
    if not bot:
        raise HTTPException(404, "Bot not found")

    token = decrypt_token(bot.token_enc)
    update = await request.json()

    msg = update.get("message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text_raw = (msg.get("text") or "")
    text = text_raw.strip().lower()

    await log_event(session, bot_id=bot.id, chat_id=chat_id, direction="in", text=text_raw)

    # настройки
    settings = (await session.execute(select(BotSettings).where(BotSettings.bot_id == bot.id))).scalar_one_or_none()
    if not settings:
        # Создаем дефолтные настройки если их нет
        default_settings = get_default_bot_settings("other", [])
        settings = BotSettings(
            bot_id=bot.id,
            greeting_text=default_settings.get("greeting_text"),
            fallback_text=default_settings.get("fallback_text"),
            services_text=default_settings.get("services_text"),
            booking_text=default_settings.get("booking_text"),
            faq_text=default_settings.get("faq_text"),
            schedule_text=default_settings.get("schedule_text"),
            location_text=default_settings.get("location_text")
        )
        session.add(settings)
        await session.commit()
        await session.refresh(settings)

    async def reply(txt: str):
        try:
            await tg_send_message(token, chat_id, txt)
            await log_event(session, bot_id=bot.id, chat_id=chat_id, direction="out", text=txt, ok=True)
        except Exception as e:
            print(f"Error sending message: {e}")
            await log_event(session, bot_id=bot.id, chat_id=chat_id, direction="out", text=txt, ok=False)

    if chat_id:
        # Обработка команд
        if text.startswith('/'):
            command = text.split()[0].lower()
            if command in ("/start", "/старт"):
                await reply(settings.greeting_text or f"Здравствуйте! Я {bot.bot_name or bot.bot_username}. Чем помочь?")
            elif command in ("/booking", "/запись"):
                await reply(settings.booking_text or "📅 Запись на услуги\n\nДля записи напишите желаемую дату и время.")
            elif command in ("/faq", "/вопросы"):
                await reply(settings.faq_text or "❓ Часто задаваемые вопросы\n\n• Используйте команды для получения информации")
            elif command in ("/services", "/услуги"):
                await reply(settings.services_text or "💰 Наши услуги и цены:\n\nИнформация о услугах временно недоступна.")
            elif command in ("/schedule", "/расписание"):
                await reply(settings.schedule_text or "🕐 Режим работы:\n\nИнформация о расписании временно недоступна.")
            elif command in ("/location", "/адрес"):
                location_msg = settings.location_text or "📍 Наш адрес:\n\nИнформация об адресе временно недоступна."
                await reply(location_msg)
            else:
                await reply("Неизвестная команда. Доступные команды:\n/start - начать\n/booking - запись\n/services - услуги\n/faq - вопросы\n/schedule - расписание\n/location - адрес")
        else:
            # Обработка обычных сообщений
            text_lower = text.lower()
            if any(word in text_lower for word in ["привет", "здравствуй", "добрый день", "hi", "hello"]):
                await reply(settings.greeting_text or f"Здравствуйте! Я {bot.bot_name or bot.bot_username}. Чем помочь?")
            elif any(word in text_lower for word in ["цена", "сколько", "стоимость", "прайс"]):
                await reply(settings.services_text or "💰 Информация о ценах временно недоступна. Используйте /services")
            elif any(word in text_lower for word in ["запис", "записать", "время", "дата"]):
                await reply(settings.booking_text or "📅 Для записи используйте команду /booking")
            elif any(word in text_lower for word in ["адрес", "где", "находится", "местоположение"]):
                await reply(settings.location_text or "📍 Информация об адресе временно недоступна. Используйте /location")
            elif any(word in text_lower for word in ["работа", "время", "режим", "график"]):
                await reply(settings.schedule_text or "🕐 Информация о расписании временно недоступна. Используйте /schedule")
            else:
                await reply(settings.fallback_text or "Могу помочь с:\n• /services - услуги и цены\n• /booking - запись на услуги\n• /schedule - режим работы\n• /faq - частые вопросы")
    return {"ok": True}
# =========================
# ====  EXTENSION HOOKS ===
# =========================
# TODO: EXT_RAG_STORAGE    — векторное хранилище (FAISS/pgvector) и эмбеддинги
# TODO: EXT_BOOKING_MODELS — таблицы расписаний/слотов/броней
# TODO: EXT_PAYMENTS       — подключение оплат (ЮKassa/СБП)
# TODO: EXT_CHANNELS       — дублирующий канал VK/OK/MiniApps
# TODO: EXT_ADMIN_UI       — админ‑метрики, статусы вебхуков, health‑пинги

# =========================
# HELPER FUNCTIONS
# =========================

def get_default_bot_settings(business_type: str, features: List[str]) -> dict:
    """Генерирует дефолтные настройки бота в зависимости от типа бизнеса и функций"""
    
    business_configs = {
        "restaurant": {
            "emoji": "🍽️",
            "name": "ресторан",
            "services": "🍴 Основные блюда:\n• Паста - от 800 ₽\n• Стейк - от 1500 ₽\n• Салаты - от 500 ₽\n• Десерты - от 300 ₽",
            "schedule": "🕐 Режим работы:\nПн-Чт: 11:00 - 23:00\nПт-Сб: 11:00 - 01:00\nВс: 12:00 - 22:00",
            "booking": "📅 Бронирование столиков:\n\nДля бронирования укажите:\n• Дату и время\n• Количество гостей\n• Контактный телефон\n\nПример: \"Завтра 19:00 на 4 человека\"",
        },
        "beauty": {
            "emoji": "💄",
            "name": "салон красоты",
            "services": "💅 Наши услуги:\n• Маникюр - от 1500 ₽\n• Педикюр - от 2000 ₽\n• Стрижка - от 1000 ₽\n• Окрашивание - от 3000 ₽\n• Укладка - от 800 ₽",
            "schedule": "🕐 Режим работы:\nПн-Пт: 9:00 - 20:00\nСб-Вс: 10:00 - 18:00",
            "booking": "📅 Запись на услуги:\n\nДля записи укажите:\n• Желаемую услугу\n• Дату и время\n• Ваше имя и телефон\n\nПример: \"Маникюр завтра в 14:00\"",
        },
        "fitness": {
            "emoji": "💪",
            "name": "фитнес-клуб",
            "services": "🏋️ Наши услуги:\n• Абонемент на месяц - от 3000 ₽\n• Персональная тренировка - от 2000 ₽\n• Групповые занятия - от 800 ₽\n• Бассейн - от 500 ₽",
            "schedule": "🕐 Режим работы:\nПн-Пт: 6:00 - 23:00\nСб-Вс: 8:00 - 22:00",
            "booking": "📅 Запись на тренировки:\n\nДля записи укажите:\n• Тип тренировки\n• Дату и время\n• Ваше имя\n\nПример: \"Йога завтра в 18:00\"",
        },
        "medical": {
            "emoji": "🏥",
            "name": "медицинский центр",
            "services": "👨‍⚕️ Наши услуги:\n• Консультация терапевта - от 1500 ₽\n• УЗИ - от 1200 ₽\n• Анализы - от 300 ₽\n• Кардиограмма - от 800 ₽",
            "schedule": "🕐 Режим работы:\nПн-Пт: 8:00 - 20:00\nСб: 9:00 - 16:00\nВс: выходной",
            "booking": "📅 Запись к врачу:\n\nДля записи укажите:\n• К какому специалисту\n• Дату и время\n• ФИО и телефон\n\nПример: \"К терапевту завтра в 10:00\"",
        }
    }
    
    config = business_configs.get(business_type, {
        "emoji": "✨",
        "name": "наша компания",
        "services": "💼 Наши услуги:\n• Консультация - от 1000 ₽\n• Основная услуга - от 2000 ₽\n• Дополнительные услуги - от 500 ₽",
        "schedule": "🕐 Режим работы:\nПн-Пт: 9:00 - 18:00\nСб-Вс: выходной",
        "booking": "📅 Запись на услуги:\n\nДля записи укажите дату, время и тип услуги.",
    })
    
    # Базовое приветствие
    greeting = f"{config['emoji']} Добро пожаловать в {config['name']}!"
    
    available_features = []
    if "booking" in features:
        available_features.append("📅 Запись на услуги")
    if "services" in features:
        available_features.append("💰 Цены и услуги")
    if "faq" in features:
        available_features.append("❓ Ответы на вопросы")
    if "schedule" in features:
        available_features.append("🕐 Режим работы")
    if "location" in features:
        available_features.append("📍 Адрес и контакты")
    
    if available_features:
        greeting += "\n\n" + "\n".join(available_features)
    
    greeting += "\n\nВыберите интересующий раздел или задайте вопрос!"
    
    return {
        "greeting_text": greeting,
        "fallback_text": f"Извините, не понял ваш запрос. Попробуйте использовать команды:\n• /services - услуги\n• /booking - запись\n• /schedule - режим работы\n• /faq - вопросы",
        "services_text": config["services"],
        "schedule_text": config["schedule"],
        "booking_text": config["booking"],
        "faq_text": "❓ Часто задаваемые вопросы:\n\n• Как записаться? - Используйте /booking\n• Какие цены? - Используйте /services\n• Время работы? - Используйте /schedule\n• Где вы находитесь? - Используйте /location",
        "location_text": "📍 Наш адрес:\n\nг. Москва, ул. Примерная, д. 123\n📞 Телефон: +7 (999) 123-45-67\n📧 Email: info@example.com",
        "contact_phone": "+7 (999) 123-45-67",
        "contact_email": "info@example.com",
        "business_address": "г. Москва, ул. Примерная, д. 123",
        "bot_description": f"Бот для {config['name']} - поможет с записью, ответит на вопросы о услугах и ценах."
    }

def get_bot_commands(features: List[str]) -> List[dict]:
    """Генерирует команды бота в зависимости от выбранных функций"""
    commands = [
        {"command": "start", "description": "Начать работу с ботом"}
    ]
    
    if "booking" in features:
        commands.append({"command": "booking", "description": "Записаться на услугу"})
    if "faq" in features:
        commands.append({"command": "faq", "description": "Частые вопросы"})
    if "services" in features:
        commands.append({"command": "services", "description": "Услуги и цены"})
    if "schedule" in features:
        commands.append({"command": "schedule", "description": "Время работы"})
    if "location" in features:
        commands.append({"command": "location", "description": "Адрес и контакты"})
    
    return commands

async def tg_set_commands(token: str, commands: List[dict]):
    """Устанавливает команды бота в Telegram"""
    try:
        url = f"{TG_BASE}/bot{token}/setMyCommands"
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={"commands": commands})
            if response.status_code != 200:
                print(f"Failed to set commands: {response.text}")
    except Exception as e:
        print(f"Error setting commands: {e}")