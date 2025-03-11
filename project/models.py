from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, Enum
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
from enum import Enum as PyEnum

# Перечисление для типов прав доступа
class PermissionTypes(str, PyEnum):
    READ = 'read'
    WRITE = 'write'

#таблица для связи групп и пользователей
group_user_association = Table(
    'group_user', Base.metadata,
    Column('group_id', Integer, ForeignKey('groups.id')),
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role', Enum(PermissionTypes))  # Роль пользователя в группе
)

# Модель для прав доступа к файлам
class FilePermission(Base):
    __tablename__ = 'file_permissions'
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    permission = Column(Enum(PermissionTypes))

    # Связи
    file = relationship("File", back_populates="permissions")
    user = relationship("User", back_populates="file_permissions")

# Модель пользователя
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    # Связи
    files = relationship("File", back_populates="owner")
    groups_created = relationship("Group", back_populates="creator")
    groups = relationship("Group", secondary=group_user_association, back_populates="users")
    file_permissions = relationship("FilePermission", back_populates="user")

# Модель группы
class Group(Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True, index=True)
    creator_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Связи
    creator = relationship("User", back_populates="groups_created")
    users = relationship("User", secondary=group_user_association, back_populates="groups")
    files = relationship("File", back_populates="group")

# Модель файла
class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    content = Column(String, default="")
    owner_id = Column(Integer, ForeignKey('users.id'))
    group_id = Column(Integer, ForeignKey('groups.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Связи
    owner = relationship("User", back_populates="files")
    group = relationship("Group", back_populates="files")
    permissions = relationship("FilePermission", back_populates="file")