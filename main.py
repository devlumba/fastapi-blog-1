from typing import Annotated
from datetime import time, timedelta, datetime, timezone


from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from .database import create_db_and_tables, reset_db
from .dependencies import SessionDep
from .users import authenticate_user, get_user
from .models import Token, TokenData, UserPublic, UserCreate, UserBase, UserInDB
from .security import create_access_token, password_hash
from .config import settings

from . import routes

app = FastAPI(openapi_tags=settings.tags_metadata)

app.include_router(routes.router, tags=["routes"])

# @app.on_event("startup")
# async def on_startup():
#     if settings.environment == "development":
#         reset_db()
#         print("Tables have been reset")
#     else:
#         create_db_and_tables()
#

@app.on_event("startup")
async def on_startup():
    create_db_and_tables()

