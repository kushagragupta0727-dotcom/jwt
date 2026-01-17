from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError

from database1 import SessionLocal, engine
import database_models
from auth_models import UserCreate, Token
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token
)

app = FastAPI()

database_models.Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def getdb():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def greet():
    return "JWT Authentication Service Running"

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(getdb)):
    if db.query(database_models.User).filter(
        database_models.User.username == user.username
    ).first():
        raise HTTPException(status_code=400, detail="User already exists")

    db_user = database_models.User(
        username=user.username,
        password=hash_password(user.password)
    )

    db.add(db_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(user: UserCreate, db: Session = Depends(getdb)):
    db_user = db.query(database_models.User).filter(
        database_models.User.username == user.username
    ).first()

    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    access_token = create_access_token({"sub": user.username})
    refresh_token = create_refresh_token({"sub": user.username})

    db.add(
        database_models.RefreshToken(
            token=refresh_token,
            username=user.username
        )
    )
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@app.post("/refresh")
def refresh_access_token(refresh_token: str, db: Session = Depends(getdb)):
    if not db.query(database_models.RefreshToken).filter(
        database_models.RefreshToken.token == refresh_token
    ).first():
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    try:
        payload = decode_token(refresh_token)
        username = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Expired or invalid refresh token")

    return {
        "access_token": create_access_token({"sub": username})
    }

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token)
        return payload.get("sub")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token"
        )

@app.get("/protected")
def protected(user: str = Depends(get_current_user)):
    return {"message": f"Hello {user}"}



