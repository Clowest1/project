ТЕКСТОВЫЙ РЕДАКТОР ДЛЯ СОВМЕСТНОЙ РАБОТЫ
Python
FastAPI
PostgreSQL
Текстовый редактор для совместной работы — это веб-приложение для совместного редактирования текстовых файлов в реальном времени. Оно построено на FastAPI, использует PostgreSQL с драйвером psycopg3 для хранения данных и Server-Sent Events (SSE) для передачи изменений между пользователями. Поддерживает авторизацию, управление группами, права доступа и версионирование файлов.
Основные возможности
Совместное редактирование: Несколько пользователей могут работать над одним файлом, получая изменения через SSE.

Авторизация: Поддержка JWT и Basic Auth (для тестирования).

Группы и права: Создание групп, назначение ролей (чтение/запись) и управление доступом к файлам.

Версионирование: Сохранение истории изменений файлов с генерацией diff.

Поддержка файлов: Текстовые файлы, Markdown и изображения.

Технологии
Backend: FastAPI (Python)

База данных: PostgreSQL с psycopg3

Реальное время: Server-Sent Events (SSE)

Авторизация: JWT, Basic Auth (временная для тестов)

ORM: SQLAlchemy (асинхронный)

Установка
Требования
Python 3.9+

PostgreSQL 13+

Git

Примечание для пользователей Windows:
Проект использует асинхронный код (asyncio, psycopg3), который может вызывать проблемы на Windows из-за ограничений событийного цикла и драйверов PostgreSQL. Рекомендуется использовать Windows Subsystem for Linux (WSL) для стабильной работы:
Установите WSL: wsl --install в PowerShell (требуется Windows 10/11).

Установите Ubuntu: wsl --install -d Ubuntu или скачайте из Microsoft Store.

Выполняйте шаги установки внутри WSL.

Шаги
Клонируйте репозиторий:
bash

git clone https://github.com/Clowest1/project.git
cd project

Создайте виртуальное окружение:
bash

python -m venv venv
source venv/bin/activate  # Linux/Mac/WSL
venv\Scripts\activate     # Windows (если не используете WSL)

Установите зависимости:
bash

pip install -r requirements.txt

Настройте окружение:
Создайте файл .env в корне проекта:

DATABASE_URL=postgresql+psycopg://username:password@localhost:5432/dbname
SECRET_KEY=your-secret-key
ALGORITHM=HS256
USE_BASIC_AUTH=true  # Для тестирования SSE

Замените username, password, dbname на ваши данные PostgreSQL.

Сгенерируйте SECRET_KEY:
bash

openssl rand -hex 32

Настройте базу данных:
Создайте базу данных в PostgreSQL:
sql

CREATE DATABASE dbname;

Таблицы создаются автоматически при запуске приложения.

Запустите приложение:
bash

uvicorn main:app --reload --port 8001

Использование:
API Эндпоинты
Регистрация: POST /register
Тело: {"username": "testuser", "password": "testpassword"}

Получение токена: POST /token
Тело: username=testuser&password=testpassword

Создание файла: POST /files/
Заголовок: Authorization: Bearer {token}

Тело: {"filename": "test.txt", "content": "Hello"}

Обновление файла: PUT /files/{file_id}
Заголовок: Authorization: Bearer {token}

Тело: "New content"

Поток изменений: GET /files/{file_id}/stream
Basic Auth: testuser:testpassword (или JWT)

Тестирование SSE:
Создайте файл через POST /files/.

Откройте в браузере: http://localhost:8001/files/{file_id}/stream.

Введите логин и пароль (Basic Auth).

Обновите файл через PUT /files/{file_id} и наблюдайте изменения в реальном времени.

Структура проекта:

project/
├── main.py         # Основной файл приложения
├── sse.py          # Логика Server-Sent Events
├── auth.py         # Авторизация
├── database.py     # Настройка базы данных
├── models.py       # Модели SQLAlchemy
├── schemas.py      # Pydantic-схемы
├── .env            # Переменные окружения (не в Git)
├── .gitignore      # Игнорируемые файлы
└── requirements.txt # Зависимости

Текущие ограничения:
Basic Auth используется для тестирования и будет заменён на JWT в продакшене.

Проблемы совместимости с Windows без WSL из-за асинхронного кода.
