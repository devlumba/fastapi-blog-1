from datetime import timezone, datetime
from typing import List

from sqlmodel import SQLModel, create_engine, select, Session, Field, Relationship
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


class UserBase(SQLModel):
    username: str | None = Field(default=None, index=True)
    email: str | None = Field(default=None, index=True)


class UserInDB(UserBase, table=True):
    id: int | None = Field(primary_key=True, default=None)
    password_hashed: str

    posts: List["PostInDB"] = Relationship(back_populates="author")


class UserPublic(UserBase):
    id: int


class UserWithPosts(UserPublic):
    posts: List["PostPublic"] = []


class UserCreate(UserBase):
    password: str


class PostBase(SQLModel):
    title: str = Field(index=True)
    content: str | None = Field(default=None, index=True)


class PostInDB(PostBase, table=True):
    id: int | None = Field(primary_key=True, default=None)
    date_posted: datetime | None = Field(default_factory=datetime.now)

    author_id: int = Field(foreign_key="userindb.id")
    author: UserInDB = Relationship(back_populates="posts")


class PostPublic(PostBase):
    id: int
    date_posted: datetime
    author: UserPublic

