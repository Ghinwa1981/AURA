# ============================================================
#  AURA :: Authentication Layer
#  JWT Tokens + bcrypt passwords
# ============================================================

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional
import uuid

from database import get_db, User

# ── Config ────────────────────────────────────────────────
SECRET_KEY  = "aura-secret-key-change-in-production-2025"
ALGORITHM   = "HS256"
TOKEN_EXPIRE_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security    = HTTPBearer(auto_error=False)

# ── Pydantic Schemas ──────────────────────────────────────
class UserRegister(BaseModel):
    username:  str
    email:     str
    password:  str
    full_name: Optional[str] = ""

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id:         str
    username:   str
    email:      str
    full_name:  str
    role:       str
    created_at: datetime

    class Config:
        from_attributes = True

# ── Password ──────────────────────────────────────────────
def hash_password(password: str) -> str:
    safe_password = password[:71]
    return pwd_context.hash(safe_password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain[:71], hashed)
    except Exception:
        return False

# ── JWT ───────────────────────────────────────────────────
def create_token(user_id: str, username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": user_id,
        "username": username,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ── Get current user (optional) ───────────────────────────
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    if not credentials:
        return None
    payload = decode_token(credentials.credentials)
    if not payload:
        return None
    user = db.query(User).filter(User.id == payload.get("sub")).first()
    return user

# ── Get current user (required) ───────────────────────────
def require_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    user = get_current_user(credentials, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user

# ── Auth Routes (add to main.py) ──────────────────────────
from fastapi import APIRouter

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])

@auth_router.post("/register")
def register(data: UserRegister, db: Session = Depends(get_db)):
    # Check existing
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username        = data.username,
        email           = data.email,
        hashed_password = hash_password(data.password),
        full_name       = data.full_name or "",
        role            = "analyst"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token(user.id, user.username)
    return {
        "message": "Account created successfully",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    }

@auth_router.post("/login")
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    token = create_token(user.id, user.username)
    return {
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@auth_router.get("/me")
def get_me(user: User = Depends(require_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "created_at": user.created_at.isoformat()
    }