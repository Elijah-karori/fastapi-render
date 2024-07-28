from fastapi import APIRouter, FastAPI, Form, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from typing import Optional, List
from enum import Enum
from jose import JWTError, jwt
from datetime import datetime, timedelta
from services.mailersend import send_email
import random
import string
from services.db import users_collection

# Constants for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_EXPIRE_MINUTES = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter(prefix="/users", tags=["users"])

def generate_otp(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# User roles
class UserRole(str, Enum):
    admin = "admin"
    customer = "customer"
    worker = "worker"

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    return users_collection.find_one({"email": email})

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
        token_data = email
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data)
    if user is None:
        raise credentials_exception
    return user

# Pydantic model for user registration
class User(BaseModel):
    email: str
    password: str
    role: UserRole
    phone_number: Optional[str] = None
    reset_password_otp: Optional[str] = None  # Field to store reset password OTP

class Token(BaseModel):
    access_token: str
    token_type: str

class OTPVerification(BaseModel):
    otp: str

@router.post("/register", response_model=User, tags=["register"])
async def register_user(user: User):
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = user.dict()
    user_dict['password'] = get_password_hash(user.password)
    user_dict['reset_password_otp'] = generate_otp()
    
    users_collection.insert_one(user_dict)
    send_email(user.email, "Account Verification", f"Your verification OTP is: {user_dict['reset_password_otp']}")
    
    return {"message": "Registration successful. Please check your email for the OTP verification code."}

@router.post("/verify-otp", response_model=User, tags=["verify"])
async def verify_otp(email: str, otp: str):
    user = get_user(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user['reset_password_otp'] != otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # OTP verified successfully
    user['reset_password_otp'] = None  # Clear OTP after successful verification
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

    # Admin or user specific OTP check
    if user['role'] == UserRole.admin:
        if user.get('last_login') and (datetime.utcnow() - user['last_login']).total_seconds() > 43200:  # 12 hours
            otp = generate_otp(8)
            send_email(user["email"], "Admin Login", f"Your OTP is: {otp}")
            return {"message": "OTP sent to email", 'otp': otp}
    elif user['role'] in [UserRole.customer, UserRole.worker]:
        otp = generate_otp(6)
        send_email(user["email"], "User Login", f"Your OTP is: {otp}")
        return {"message": "OTP sent to email", 'otp': otp}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )

    # Update last login time
    users_collection.update_one({"email": form_data.username}, {"$set": {"last_login": datetime.utcnow()}})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login/verify-otp", response_model=Token, tags=["login"])
async def login_verify_otp(email: str, otp: OTPVerification):
    user = get_user(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user['role'] == UserRole.admin and user.get('last_login') and (datetime.utcnow() - user['last_login']).total_seconds() > 43200:
        # Admin requires OTP verification
        if user['reset_password_otp'] != otp.otp:
            raise HTTPException(status_code=401, detail="Invalid OTP")

        # Clear OTP and update last login time
        users_collection.update_one({"email": email}, {"$set": {"reset_password_otp": None, "last_login": datetime.utcnow()}})
    elif user['reset_password_otp'] != otp.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users", response_model=List[User])
async def get_users():
    users = list(users_collection.find({}, {"_id": 0, "password": 0, "reset_password_otp": 0}))
    return users
