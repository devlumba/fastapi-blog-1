from typing import Annotated
from datetime import time, timedelta, datetime, timezone


from fastapi import FastAPI, Depends, HTTPException, APIRouter, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import select

from .database import create_db_and_tables
from .dependencies import SessionDep, get_current_user
from .users import authenticate_user, get_user
from .models import Token, TokenData, UserPublic, UserCreate, UserBase, UserInDB, PostBase, PostInDB, PostPublic, UserWithPosts
from .security import create_access_token, password_hash
from .config import settings


router = APIRouter()


@router.post("/token", summary="should hide from openapi_schema?")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)],
        session: SessionDep
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.post("/users/", response_model=UserPublic)
async def create_user(user: UserCreate, session: SessionDep):
    existing_user = get_user(session, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="User with that username already exists")

    user_data = user.model_dump()
    password_hashed = password_hash.hash(user.password)
    user_db = UserInDB(**user_data, password_hashed=password_hashed)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return user_db


@router.get("/users/", response_model=list[UserPublic])
async def read_users(session: SessionDep):
    users = session.exec(select(UserInDB)).all()
    return users


@router.get("/users/{user_id}", response_model=UserWithPosts)
async def read_user(user_id: int, session: SessionDep):
    user = session.get(UserInDB, user_id)
    return user


@router.post("/posts/", response_model=PostPublic)
async def create_post(current_user: Annotated[UserInDB, Depends(get_current_user)],
                      post: PostBase,  # I assume I'll have to use forms later on?
                      session: SessionDep):
    if not current_user:
        return HTTPException(status_code=403, detail="Must be logged in to create posts!")
    post_data = post.model_dump()
    post_db = PostInDB(**post_data, author_id=current_user.id)
    session.add(post_db)
    session.commit()
    return post_db


@router.get("/posts/", response_model=list[PostPublic])
async def read_posts(session: SessionDep):
    posts = session.exec(select(PostInDB)).all()
    return posts
