import os
from dotenv import load_dotenv
from jose import jwt
from datetime import datetime, timedelta, timezone

# BASEDIR = os.path.abspath(os.path.dirname(__file__))
BASEDIR = os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
load_dotenv(os.path.join(BASEDIR, '.env'))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

def authenticate_user(username: str, password: str):
    # print("user:", username)
    # print("ADMIN_USERNAME:", ADMIN_USERNAME)
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"username": username}
    return False

SECRET_KEY=os.getenv("SECRET_KEY")
ALGORITHM=os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            raise credentials_exception

        user = {"username": username}
    except JWTError:
        raise credentials_exception

    return user