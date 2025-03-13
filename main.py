from fastapi.middleware.cors import CORSMiddleware
import uuid
from fastapi import FastAPI, Depends, HTTPException, status, Body, Response, File as FastAPIFile, UploadFile, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from database import AsyncSessionLocal, engine
from models import Base, User, Group, File, FilePermission, PermissionTypes, group_user_association, FileLink, FileVersion
from schemas import UserCreate, User as UserSchema, GroupCreate, Group as GroupSchema, FileCreate, File as FileSchema, FilePermissionBase, GroupWithRole as GroupWithRoleSchema
from auth import authenticate_user, create_access_token, get_password_hash, oauth2_scheme, SECRET_KEY, ALGORITHM
from sse import event_stream, notify_file_change
from datetime import timedelta
from typing import List, Optional
from decouple import config
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import jwt
import asyncio
import sys
from sqlalchemy import text, distinct
from datetime import datetime
import mimetypes
import logging
from difflib import unified_diff
import json
from starlette.responses import StreamingResponse

# Создание приложения FastAPI
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://localhost:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

# Проверка подключения к базе данных при старте
async def test_connection():
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            print(f"Test query result: {result.fetchone()}")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        raise

# Создание таблиц в базе данных, но нам нужно именно ассинхронное 
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Зависимость для получения сессии базы данных
async def get_db():
    async with AsyncSessionLocal() as db:
        yield db

@app.on_event("startup")
async def startup_event():
    await test_connection()  # Проверка подключения
    await init_db() 

# Регистрация пользователя
@app.post("/register", response_model=UserSchema)
async def register(user:UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalars().first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return {"id": db_user.id, "username": db_user.username}

# Аутентификация и получение токена
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user


# Функция для проверки Basic Auth
async def get_current_user_basic(
    credentials: HTTPBasicCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """
    Проверяет пользователя через Basic Auth.
    """
    user = await authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

# Создание группы
@app.post("/groups/", response_model=GroupSchema)
async def create_group(group: GroupCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_group = Group(creator_id=current_user.id)
    db.add(db_group)
    await db.commit()
    await db.refresh(db_group)
    return {"id": db_group.id, "creator_id": db_group.creator_id, "created_at": db_group.created_at}

# Добавление пользователей в группу c ролями
@app.post("/groups/{group_id}/add_users")
async def add_users_to_group(group_id: int, user_ids: List[int], roles: List[str], db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalars().first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the creator can add users")
    result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users = result.scalars().all()
    if len(users) != len(user_ids) or len(users) != len(roles):
        raise HTTPException(status_code=400, detail="Mismatch in user_ids and roles length")
    for user, role in zip(users, roles):
        if role not in ['read', 'write']:
            raise HTTPException(status_code=400, detail="Role must be 'read' or 'write'")
        exists = await db.execute(
            select(group_user_association).where(
                group_user_association.c.group_id == group.id,
                group_user_association.c.user_id == user.id
            )
        ) 
        if not exists.scalar():
            await db.execute(
                group_user_association.insert().values(
                    group_id=group_id,
                    user_id=user.id,
                    role=role
                )
            )
        file_result = await db.execute(select(File).where(File.group_id == group_id))
        files = file_result.scalars().all()
        for file in files:
            # Проверяем, существует ли уже право
            result = await db.execute(
                select(FilePermission).where(
                    FilePermission.file_id == file.id,
                    FilePermission.user_id == user.id
                )
            )
            file_permission = result.scalars().first()
            if not file_permission:
                file_permission = FilePermission(file_id=file.id, user_id=user.id, permission=role)
                db.add(file_permission)
            elif file_permission.permission != role:
                file_permission.permission = role
    await db.commit()
    return {"message": "Users added to group with roles"}


# Удаление пользователей из группы
@app.post("/groups/{group_id}/remove_users")
async def remove_users_from_group(group_id: int, user_ids: List[int], db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Group).where(Group.id == group_id))
    group = result.scalars().first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the creator can remove users")
    result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users = result.scalars().all()
    if len(users) != len(user_ids):
        raise HTTPException(status_code=400, detail="Some users not found")
    
    for user in users:
        # Удаляем связь из group_user_association
        await db.execute(
            group_user_association.delete().where(
                group_user_association.c.group_id == group_id,
                group_user_association.c.user_id == user.id
            )
        )
        # Удаляем права доступа к файлам группы
        await db.execute(
            FilePermission.__table__.delete().where(
                FilePermission.file_id.in_(
                    select(File.id).where(File.group_id == group_id)
                ),
                FilePermission.user_id == user.id
            )
        )
    await db.commit()
    return {"message": "Users removed from group"}


# Создание файла
@app.post("/files/", response_model=FileSchema)
async def create_file(file: FileCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Если group_id указан, проверяем, что он принадлежит текущему пользователю
    if file.group_id is not None:
        result = await db.execute(select(Group).where(Group.id == file.group_id, Group.creator_id == current_user.id))
        group = result.scalars().first()
        if not group:
            raise HTTPException(status_code=403, detail="You can only assign files to your own groups")
        group_id = group.id
    else:
        group_id = None

    # Создаём файл
    db_file = File(
        filename=file.filename,
        content=file.content,
        owner_id=current_user.id,
        group_id=group_id
    )
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)

    # Создаём ссылку в базе
    link_uuid = str(uuid.uuid4())
    expires_at = datetime.utcnow()+timedelta(days=7)
    db_link = FileLink(link_uuid=link_uuid, file_id=db_file.id, expires_at=expires_at)
    db.add(db_link)
    await db.commit()
    await db.refresh(db_link)

    file_url = f"http://localhost:8001/files/link/{link_uuid}"

    # Возвращаем полный ответ иначе ошибка вылазит(аналогично как я до этого делал)
    return {
        "id": db_file.id,
        "filename": db_file.filename,
        "content": db_file.content,
        "owner_id": db_file.owner_id,
        "group_id": db_file.group_id,
        "created_at": db_file.created_at,
        "updated_at": db_file.updated_at,
        "link": file_url
    }

# Изменение файла
@app.put("/files/{file_id}", response_model=FileSchema)
async def update_file(file_id: int, content: str = Body(...), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user), background_tasks: BackgroundTasks = None):
    result = await db.execute(select(File).where(File.id == file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    await check_file_permission(db, file_id, current_user.id, 'write')

    # Получаем предыдущую версию файла
    result = await db.execute(select(FileVersion).where(FileVersion.file_id == file_id).order_by(FileVersion.version.desc()))
    last_version = result.scalars().first()
    old_content = last_version.content if last_version else db_file.content

    # Сохраняем текущую версию
    new_version = FileVersion(file_id=file_id, content=old_content, version=(last_version.version + 1 if last_version else 1))
    db.add(new_version)

    # Обновляем файл
    db_file.content = content
    db_file.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(db_file)
    logger.info(f"Calling notify_file_change for file {file_id} with diff")

    # Генерируем diff между старым и новым содержимым
    diff_lines = list(unified_diff(
        old_content.splitlines(keepends=True),
        content.splitlines(keepends=True),
        fromfile='old',
        tofile='new',
        lineterm=''
    ))
    diff_data = {
        "file_id": file_id,
        "diff": diff_lines  # Diff в формате unified diff
    }

    if background_tasks:
        background_tasks.add_task(notify_file_change, file_id, diff_data)

    result = await db.execute(select(FileLink).where(FileLink.file_id == file_id))
    db_link = result.scalars().first()
    file_url = f"http://localhost:8001/files/link/{db_link.link_uuid}" if db_link else None

    return {"id": db_file.id, "filename": db_file.filename, "content": db_file.content, "owner_id": db_file.owner_id, "group_id": db_file.group_id, "created_at": db_file.created_at, "updated_at": db_file.updated_at, "link": file_url}

# Удаление файла
@app.delete("/files/{file_id}")
async def delete_file(file_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(File).where(File.id == file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can delete the file")
    await db.delete(db_file)
    await db.commit()
    return {"message": "File deleted"}

#загрузка изображений в файлы
@app.post("/files/upload-image/", response_model=FileSchema)
async def upload_image(
    file: UploadFile = FastAPIFile(...),
    group_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are allowed")
    content = await file.read()
    if group_id:
        result = await db.execute(select(Group).where(Group.id == group_id, Group.creator_id == current_user.id))
        group = result.scalars().first()
        if not group:
            raise HTTPException(status_code=403, detail="You can only assign files to your own groups")
    
    db_file = File(filename=file.filename, content=content.hex(), owner_id=current_user.id, group_id=group_id)
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    
    # Создаём ссылку в базе
    link_uuid = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_link = FileLink(link_uuid=link_uuid, file_id=db_file.id, expires_at=expires_at)
    db.add(db_link)
    await db.commit()
    await db.refresh(db_link)
    
    file_url = f"http://localhost:8001/files/link/{link_uuid}"
    return {
        "id": db_file.id,
        "filename": db_file.filename,
        "content": db_file.content,
        "owner_id": db_file.owner_id,
        "group_id": db_file.group_id,
        "created_at": db_file.created_at,
        "updated_at": db_file.updated_at,
        "link": file_url
    }

@app.post("/files/markdown/", response_model=FileSchema)
async def create_markdown_file(
    filename: str = Form(...),
    content: str = Form(...),
    group_id: Optional[int] = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not filename.lower().endswith(".md"):
        filename += ".md"
    
    if group_id:
        result = await db.execute(select(Group).where(Group.id == group_id, Group.creator_id == current_user.id))
        group = result.scalars().first()
        if not group:
            raise HTTPException(status_code=403, detail="You can only assign files to your own groups")
    
    db_file = File(filename=filename, content=content, owner_id=current_user.id, group_id=group_id)
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    
    link_uuid = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_link = FileLink(link_uuid=link_uuid, file_id=db_file.id, expires_at=expires_at)
    db.add(db_link)
    await db.commit()
    await db.refresh(db_link)
    
    file_url = f"http://localhost:8001/files/link/{link_uuid}"
    return {
        "id": db_file.id,
        "filename": db_file.filename,
        "content": db_file.content,
        "owner_id": db_file.owner_id,
        "group_id": db_file.group_id,
        "created_at": db_file.created_at,
        "updated_at": db_file.updated_at,
        "link": file_url
    }

@app.post("/files/{file_id}/link")
async def create_file_link(file_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(File).where(File.id == file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to create link for this file")
    
    link_uuid = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=7)
    db_link = FileLink(link_uuid=link_uuid, file_id=file_id, expires_at=expires_at)
    db.add(db_link)
    await db.commit()
    await db.refresh(db_link)
    
    file_url = f"http://localhost:8001/files/link/{link_uuid}"
    return {"file_id": file_id, "link": file_url}

#получение файла по ссылке
@app.get("/files/link/{link_uuid}")
async def get_file_by_link(link_uuid: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FileLink).where(FileLink.link_uuid == link_uuid))
    db_link = result.scalars().first()
    if not db_link:
        raise HTTPException(status_code=404, detail="Link not found")
    
    result = await db.execute(select(File).where(File.id == db_link.file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    return {
        "id": db_file.id,
        "filename": db_file.filename,
        "content": db_file.content,
        "owner_id": db_file.owner_id,
        "group_id": db_file.group_id,
        "created_at": db_file.created_at,
        "updated_at": db_file.updated_at,
        "link": f"http://localhost:8001/files/link/{link_uuid}"
    }

# Новый эндпоинт для получения изображения как потока байтов
@app.get("/files/link/{link_uuid}/image")
async def get_file_image_by_link(
    link_uuid: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Получаем ссылку из базы
    result = await db.execute(select(FileLink).where(FileLink.link_uuid == link_uuid))
    db_link = result.scalars().first()
    if not db_link:
        raise HTTPException(status_code=404, detail="Link not found")
    if db_link.expires_at and db_link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Link has expired")
    # Получаем файл
    result = await db.execute(select(File).where(File.id == db_link.file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Проверяем права доступа
    await check_file_permission(db, db_file.id, current_user.id, 'read')
    
    # Преобразуем HEX-строку в байты
    try:
        image_bytes = bytes.fromhex(db_file.content)  
    except ValueError:
        raise HTTPException(status_code=500, detail="Invalid image data in database")
    
    # Определяем MIME-тип динамически по имени файла
    mime_type, _ = mimetypes.guess_type(db_file.filename)
    if not mime_type or not mime_type.startswith("image/"):
        # Значение по умолчанию, если тип не определён
        mime_type = "image/png" if db_file.filename.lower().endswith(".png") else "image/jpeg"
    
    return Response(content=image_bytes, media_type=mime_type)

# Назначение прав доступа к файлу
@app.post("/files/{file_id}/permissions")
async def set_file_permission(file_id: int, user_id: int, permission: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(File).where(File.id == file_id))
    file = result.scalars().first()
    if not file or file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the file owner can set permissions")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    result = await db.execute(
        select(FilePermission).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id
        )
    )
    file_permission = result.scalars().first()
    if file_permission:
        file_permission.permission = permission
    else:
        file_permission = FilePermission(file_id=file_id, user_id=user_id, permission=permission)
        db.add(file_permission)
    await db.commit()
    return {"message": "Permission updated"}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Проверка прав доступа
async def check_file_permission(db: AsyncSession, file_id: int, user_id: int, required_permission: str):
    logger.info(f"Checking permission for user_id={user_id}, file_id={file_id}, required_permission={required_permission}")
    
    result = await db.execute(select(File).where(File.id == file_id))
    file = result.scalars().first()
    if not file:
        logger.error(f"File with id={file_id} not found")
        raise HTTPException(status_code=404, detail="File not found")
    
    # Проверка, является ли пользователь владельцем
    if file.owner_id == user_id:
        logger.info(f"User {user_id} is the owner of file {file_id}")
        return True
    
    # Если файл принадлежит группе
    if file.group_id:
        logger.info(f"File {file_id} belongs to group {file.group_id}")
        # Проверяем роль пользователя в группе
        result = await db.execute(
            select(group_user_association).where(
                group_user_association.c.group_id == file.group_id,
                group_user_association.c.user_id == user_id
            )
        )
        group_role = result.scalars().first()  # Получаем объект или None
        logger.debug(f"Group role for user {user_id} in group {file.group_id}: {group_role}")
        if group_role and hasattr(group_role, 'role') and group_role.role == required_permission.upper():
            logger.info(f"User {user_id} has {group_role.role} permission for group {file.group_id}")
            return True
        # Если роли нет или она не соответствует required_permission, проверяем прямые права
        result = await db.execute(select(FilePermission).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id
        ))
        permission = result.scalars().first()
        if not permission:
            logger.error(f"No direct permission found for user {user_id} on file {file_id}")
            raise HTTPException(status_code=403, detail="You do not have access to this file")
        if permission.permission == 'none':
            logger.error(f"Permission for user {user_id} on file {file_id} is 'none'")
            raise HTTPException(status_code=403, detail="You do not have access to this file")
        if required_permission == 'write' and permission.permission != 'write':
            logger.error(f"User {user_id} lacks write permission for file {file_id}")
            raise HTTPException(status_code=403, detail="You do not have write access to this file")
        logger.info(f"User {user_id} has {permission.permission} direct permission for file {file_id}")
    else:
        # Если файл не принадлежит группе, проверяем только прямые права
        logger.info(f"File {file_id} does not belong to any group")
        result = await db.execute(select(FilePermission).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id
        ))
        permission = result.scalars().first()
        if not permission:
            logger.error(f"No direct permission found for user {user_id} on file {file_id}")
            raise HTTPException(status_code=403, detail="You do not have access to this file")
        if permission.permission == 'none':
            logger.error(f"Permission for user {user_id} on file {file_id} is 'none'")
            raise HTTPException(status_code=403, detail="You do not have access to this file")
        if required_permission == 'write' and permission.permission != 'write':
            logger.error(f"User {user_id} lacks write permission for file {file_id}")
            raise HTTPException(status_code=403, detail="You do not have write access to this file")
        logger.info(f"User {user_id} has {permission.permission} direct permission for file {file_id}")
    
    return True


# Обновлённый эндпоинт для SSE с поддержкой Basic Auth как альтернативы JWT
@app.get("/files/{file_id}/stream")
async def stream_file(
    file_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_basic),  # Используем только Basic Auth
):
    await check_file_permission(db, file_id, current_user.id, 'read')
    return StreamingResponse(event_stream(file_id), media_type="text/event-stream")

@app.get("/files/link/{link_uuid}/download-markdown")
async def download_markdown_by_link(link_uuid: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(FileLink).where(FileLink.link_uuid == link_uuid))
    db_link = result.scalars().first()
    if not db_link:
        raise HTTPException(status_code=404, detail="Link not found")
    if db_link.expires_at and db_link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Link has expired")
    
    result = await db.execute(select(File).where(File.id == db_link.file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    await check_file_permission(db, db_file.id, current_user.id, 'read')
    if not db_file.filename.lower().endswith(".md"):
        raise HTTPException(status_code=400, detail="File is not a Markdown document")
    
    return Response(
        content=db_file.content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=\"{db_file.filename}\""}
    )


# Функция получения всех файлов пользователя(для главной страницы)
@app.get("/files/my", response_model=List[FileSchema])
async def get_my_files(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(File).where(File.owner_id == current_user.id))
    files = result.scalars().all()
    
    file_list = []
    for db_file in files:
        result = await db.execute(select(FileLink).where(FileLink.file_id == db_file.id))
        db_link = result.scalars().first()
        file_url = f"http://localhost:8001/files/link/{db_link.link_uuid}" if db_link else None
        file_list.append({
            "id": db_file.id,
            "filename": db_file.filename,
            "content": db_file.content,
            "owner_id": db_file.owner_id,
            "group_id": db_file.group_id,
            "created_at": db_file.created_at,
            "updated_at": db_file.updated_at,
            "link": file_url
        })
    return file_list

@app.get("/groups/my", response_model=List[GroupWithRoleSchema])
async def get_my_groups(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    logger.info(f"Fetching groups for user {current_user.username} (ID: {current_user.id})")
    
    # Получаем группы, где пользователь является участником
    participant_query = (
        select(
            Group.id,
            Group.creator_id,
            Group.created_at,
            group_user_association.c.role.label('role')
        ).join(
            group_user_association,
            Group.id == group_user_association.c.group_id,
            isouter=True
        ).where(
            group_user_association.c.user_id == current_user.id
        ).order_by(Group.created_at.desc())
    )
    participant_result = await db.execute(participant_query)
    participant_groups = participant_result.all()

    # Получаем группы, созданные пользователем (где он владелец), но которые могут не быть в group_user
    creator_query = (
        select(
            Group.id,
            Group.creator_id,
            Group.created_at
        ).where(
            Group.creator_id == current_user.id
        ).order_by(Group.created_at.desc())
    )
    creator_result = await db.execute(creator_query)
    creator_groups = creator_result.all()

    # Формируем список групп с ролями
    group_list = []
    processed_group_ids = set()  # Для избежания дублирования

    # Сначала добавляем группы, где пользователь участник
    for group_id, creator_id, created_at, role in participant_groups:
        if group_id:  # Проверяем, что группа существует
            group_list.append({
                "id": group_id,
                "creator_id": creator_id,
                "created_at": created_at,
                "role": role if role else "none"
            })
            processed_group_ids.add(group_id)

    # Затем добавляем группы, созданные пользователем, с ролью "owner"
    for group_id, creator_id, created_at in creator_groups:
        if group_id not in processed_group_ids:
            group_list.append({
                "id": group_id,
                "creator_id": creator_id,
                "created_at": created_at,
                "role": "owner"  # Роль владельца (создателя)
            })
            processed_group_ids.add(group_id)

    logger.info(f"Returning groups for user {current_user.username}: {group_list}")
    return group_list