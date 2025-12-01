from typing import Annotated
from datetime import time, timedelta, datetime, timezone

import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, create_engine, select, Session, Field
from pwdlib import PasswordHash
from pydantic import BaseModel
from jwt.exceptions import InvalidTokenError


sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM =  "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


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


class UserPublic(UserBase):
    id: int


class UserCreate(UserBase):
    password: str


password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


@app.on_event("startup")
async def on_startup():
    create_db_and_tables()


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_user(db, username: str) -> UserInDB:
    user = db.exec(select(UserInDB).where(UserInDB.username == username)).first()
    return user


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password_hashed):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep):
    credentials_exception = HTTPException(
        status_code=401, detail="Couldn't validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(session, username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)],
        session: SessionDep
) -> Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/users/", response_model=UserPublic)
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

