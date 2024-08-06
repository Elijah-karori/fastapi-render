from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
import jwt
from datetime import datetime, timedelta
import random
import string
from services.mailersend import send_email
from services.db import users_collection

# Constants for JWT
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter(prefix="/users", tags=["users"])

# User roles
class UserRole(str, Enum):
    admin = "admin"
    customer = "customer"
    worker = "worker"

class User(BaseModel):
    email: str
    password: str
    role: UserRole
    phone_number: Optional[str] = None
    reset_password_otp: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class OTPVerification(BaseModel):
    otp: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    return users_collection.find_one({"email": email})

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user or not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except (jwt.JWTError, jwt.InvalidTokenError):
        raise credentials_exception

    user = get_user(email=email)
    if user is None:
        raise credentials_exception
    return user

def generate_otp(length: int = 6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@router.post("/register", response_model=User)
async def register_user(user: User):
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_dict = user.dict()
    user_dict['password'] = get_password_hash(user.password)
    user_dict['reset_password_otp'] = generate_otp(8)

    users_collection.insert_one(user_dict)
    send_email(user.email, "Your OTP Verification Code", f"Your OTP is: {user_dict['reset_password_otp']}")

    return {"message": "Registration successful. Please check your email for the OTP verification code."}

@router.post("/verify-otp")
async def verify_otp(email: str, otp: str):
    user = get_user(email)
    if not user or user['reset_password_otp'] != otp:
        raise HTTPException(status_code=401, detail="Invalid OTP or User not found")

    users_collection.update_one({"email": email}, {"$set": {"reset_password_otp": None}})
    return {"message": "OTP verified successfully. You can now log in."}

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user['role'] in [UserRole.admin, UserRole.customer, UserRole.worker]:
        otp = generate_otp(8 if user['role'] == UserRole.admin else 6)
        users_collection.update_one({"email": form_data.username}, {"$set": {"reset_password_otp": otp}})
        send_email(user["email"], "Your OTP Verification Code", f"Your OTP is: {otp}")
        return {"message": "OTP sent to email"}

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["email"]}, expires_delta=access_token_expires)
    users_collection.update_one({"email": form_data.username}, {"$set": {"last_login": datetime.utcnow()}})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login/verify-otp", response_model=Token)
async def login_verify_otp(email: str, otp: OTPVerification):
    user = get_user(email)
    if not user or user['reset_password_otp'] != otp.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP or User not found")

    users_collection.update_one({"email": email}, {"$set": {"reset_password_otp": None, "last_login": datetime.utcnow()}})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/", response_model=List[User])
async def get_users():
    users = list(users_collection.find({}, {"_id": 0, "password": 0, "reset_password_otp": 0}))
    return users
