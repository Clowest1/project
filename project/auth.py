from fastapi import Depends, HTTPException, status  # Импорт для обработки ошибок
from fastapi.security import OAuth2PasswordBearer  # Схема для аутентификации
import jwt  # Работа с JWT-токенами
from passlib.context import CryptContext  # Хэширование паролей
from datetime import datetime, timedelta  # Работа с датами
from database import AsyncSessionLocal, AsyncSession  # Асинхронная сессия базы данных
from models import User  # Модель пользователя
from decouple import config  # Загрузка переменных окружения
from jwt import PyJWTError #ошибка((
from sqlalchemy.future import select

# Загрузка настроек из .env
SECRET_KEY = config("SECRET_KEY")  # Секретный ключ для JWT
ALGORITHM = config("ALGORITHM", default="HS256")  # Алгоритм шифрования
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Время жизни токена

# Контекст для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема для аутентификации через OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Функция для хэширования пароля
def get_password_hash(password):
    return pwd_context.hash(password)

# Функция для аутентификации пользователя
async def authenticate_user(username: str, password: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalars().first() #получегие первого пользователя из результата
        if not user or not verify_password(password, user.hashed_password):
            return False
        return user

# Функция для создания JWT-токена
def create_access_token(data: dict, expires_delta: timedelta = None):
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except PyJWTError as e:
        raise HTTPException(status_code=500, detail=f"JWT encoding error: {e}")

