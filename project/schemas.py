from pydantic import BaseModel, Field, validator, constr
from datetime import datetime
from typing import List, Optional

class FeatureBase(BaseModel):
    class Config:
        from_attributes = True


# Валидация для имени пользователя
class UserBase(FeatureBase):
    username: constr(min_length=3, max_length=50)

# Валидация для пароля
passwordConstr = constr(min_length=8)
class UserCreate(UserBase):
    password: passwordConstr

# Схема пользователя для ответа
class User(UserBase):
    id: int
    
# Валидация для группы
class GroupBase(FeatureBase):
    creator_id: int

class GroupCreate(GroupBase):
    user_ids: List[int]
    roles: List[str]

class Group(GroupBase):
    id: int
    created_at: datetime
    

# Валидация для файла
class FileBase(FeatureBase):
    filename: constr(min_length=1, max_length=100)

class FileCreate(FileBase):
    content: constr(min_length=1)

class File(FileBase):
    id: int
    owner_id: int
    group_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    

# Валидация для прав доступа
class FilePermissionBase(FeatureBase):
    file_id: int
    user_id: int
    permission: str

    @validator('permission')
    def validate_permission(cls, v):
        if v not in ['read', 'write']:
            raise ValueError('Permission must be "read" or "write"')
        return v

class FilePermission(FilePermissionBase):
    id: int
    