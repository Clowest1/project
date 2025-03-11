from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession  # Асинхронные компоненты SQLAlchemy
from sqlalchemy.orm import sessionmaker, declarative_base  # создаь сессию и базовый класс для моделей
from decouple import config  # Загрузка переменных окружения

SQLALCHEMY_DATABASE_URL = config("DATABASE_URL")
print(f"Attempting to connect to: {SQLALCHEMY_DATABASE_URL}")

engine = create_async_engine(SQLALCHEMY_DATABASE_URL, future=True, echo=True, pool_size=10, pool_pre_ping=True, max_overflow=0)
print("Engine created successfully")
    
# Создание асинхронной сессии
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

# Функция для получения асинхронной сессии
async def get_async_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session