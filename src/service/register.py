


from pydantic import EmailStr, SecretStr
from sqlmodel import select
import uuid
from typing_extensions import Annotated

from fastapi import Form

from pwdlib import PasswordHash

from src.database import SessionDep
from src.models import User
from src.schemas import RegisterRequest

password_hasher = PasswordHash.recommended()

def register_user(
    data: RegisterRequest,
    session: SessionDep
) -> uuid.UUID | None:
    if user := session.exec(select(User).where(User.email == data.email)).first():
        return user.id

    user = User(
        email=data.email,
        username=data.email
    )
    user.set_password(data.password)
    session.add(user)
    session.commit()
    return user.id
