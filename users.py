from sqlmodel import select

from .models import UserInDB
from .security import verify_password


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

