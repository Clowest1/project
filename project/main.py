from fastapi import FastAPI, Depends, HTTPException, status, Body, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import AsyncSessionLocal, engine
from models import Base, User, Group, File, FilePermission, PermissionTypes
from schemas import UserCreate, User as UserSchema, GroupCreate, Group as GroupSchema, FileCreate, File as FileSchema, FilePermissionBase
from auth import authenticate_user, create_access_token, get_password_hash, oauth2_scheme, SECRET_KEY, ALGORITHM
from sse import event_stream, notify_file_change
from datetime import timedelta
from typing import List, Optional
from decouple import config
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import jwt
import asyncio
from asyncio import WindowsSelectorEventLoopPolicy
import sys

# Настройка событийного цикла для Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())

# Создание приложения FastAPI
app = FastAPI()

# Проверка подключения к базе данных при старте
async def test_connection():
    try:
        async with engine.connect() as conn:
            result = await conn.execute("SELECT 1")
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
    return db_user

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

# Создание группы
@app.post("/groups/", response_model=GroupSchema)
async def create_group(group: GroupCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_group = Group(creator_id=current_user.id)
    db.add(db_group)
    await db.commit()
    await db.refresh(db_group)
    return db_group

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
        group.users.append(user)
        for file in group.files:
            file_permission = FilePermission(file_id=file.id, user_id=user.id, permission=role)
            db.add(file_permission)
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
    for user in users:
        group.users.remove(user)
        await db.execute(
            FilePermission.__table__.delete().where(
                FilePermission.file_id.in_([file.id for file in group.files]),
                FilePermission.user_id == user.id
            )
        )
    await db.commit()
    return {"message": "Users removed from group"}


# Создание файла
@app.post("/files/", response_model=FileSchema)
async def create_file(file: FileCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_file = File(filename=file.filename, content=file.content, owner_id=current_user.id)
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    return db_file

# Изменение файла
@app.put("/files/{file_id}", response_model=FileSchema)
async def update_file(file_id: int, content: str = Body(...), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(File).where(File.id == file_id))
    db_file = result.scalars().first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    if db_file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can update the file")
    db_file.content = content
    await db.commit()
    await db.refresh(db_file)
    notify_file_change(file_id, content)
    return db_file

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

# Проверка прав доступа
async def check_file_permission(db: AsyncSession, file_id: int, user_id: int, required_permission: str):
    result = await db.execute(select(File).where(File.id == file_id))
    file = result.scalars().first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    if file.owner_id == user_id:
        return True
    result = await db.execute(select(FilePermission).where(
        FilePermission.file_id == file_id,
        FilePermission.user_id == user_id
    ))
    permission = result.scalars().first()
    if not permission or permission.permission == 'none':
        raise HTTPException(status_code=403, detail="You do not have access to this file")
    if required_permission == 'write' and permission.permission != 'write':
        raise HTTPException(status_code=403, detail="You do not have write access to this file")
    return True


# SSE для обновлений файла
@app.get("/files/{file_id}/stream")
async def stream_file(file_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    await check_file_permission(db, file_id, current_user.id, 'read')
    return await event_stream(file_id)