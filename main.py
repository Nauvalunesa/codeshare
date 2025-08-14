from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import json
from typing import Optional, List
import os
from decouple import config

app = FastAPI(title="Lunox Clone - Code Sharing Platform")

# Security
SECRET_KEY = config("SECRET_KEY", default="your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Templates
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Cassandra connection
def get_cassandra_session():
    cluster = Cluster(['127.0.0.1'])
    session = cluster.connect()
    
    # Create keyspace if not exists
    session.execute("""
        CREATE KEYSPACE IF NOT EXISTS lunox
        WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}
    """)
    
    session.set_keyspace('lunox')
    
    # Create tables
    session.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT,
            email TEXT,
            password_hash TEXT,
            created_at TIMESTAMP,
            badges SET<TEXT>
        )
    """)
    
    session.execute("""
        CREATE TABLE IF NOT EXISTS pastes (
            id UUID PRIMARY KEY,
            title TEXT,
            content TEXT,
            language TEXT,
            author_id UUID,
            author_username TEXT,
            is_private BOOLEAN,
            password_hash TEXT,
            views COUNTER,
            created_at TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)
    
    session.execute("""
        CREATE TABLE IF NOT EXISTS threads (
            id UUID PRIMARY KEY,
            paste_id UUID,
            author_id UUID,
            author_username TEXT,
            content TEXT,
            created_at TIMESTAMP
        )
    """)
    
    session.execute("""
        CREATE TABLE IF NOT EXISTS paste_views (
            paste_id UUID,
            view_date DATE,
            views COUNTER,
            PRIMARY KEY (paste_id, view_date)
        )
    """)
    
    return session

session = get_cassandra_session()

# Auth functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/api/signup")
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    # Check if user exists
    existing_user = session.execute(
        "SELECT username FROM users WHERE username = ? ALLOW FILTERING",
        [username]
    ).one()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user_id = uuid.uuid4()
    password_hash = get_password_hash(password)
    
    session.execute("""
        INSERT INTO users (id, username, email, password_hash, created_at, badges)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [user_id, username, email, password_hash, datetime.now(), {'newcomer'}])
    
    # Create token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):
    user = session.execute(
        "SELECT username, password_hash FROM users WHERE username = ? ALLOW FILTERING",
        [username]
    ).one()
    
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/create", response_class=HTMLResponse)
async def create_paste_page(request: Request):
    return templates.TemplateResponse("create.html", {"request": request})

@app.post("/api/paste")
async def create_paste(
    title: str = Form(...),
    content: str = Form(...),
    language: str = Form(default="text"),
    is_private: bool = Form(default=False),
    password: Optional[str] = Form(default=None),
    expires_hours: int = Form(default=0),
    current_user: str = Depends(get_current_user)
):
    paste_id = uuid.uuid4()
    password_hash = get_password_hash(password) if password else None
    expires_at = datetime.now() + timedelta(hours=expires_hours) if expires_hours > 0 else None
    
    # Get user info
    user = session.execute(
        "SELECT id FROM users WHERE username = ? ALLOW FILTERING",
        [current_user]
    ).one()
    
    session.execute("""
        INSERT INTO pastes (id, title, content, language, author_id, author_username, 
                          is_private, password_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [paste_id, title, content, language, user.id, current_user, 
          is_private, password_hash, datetime.now(), expires_at])
    
    return {"paste_id": str(paste_id)}

@app.get("/paste/{paste_id}", response_class=HTMLResponse)
async def view_paste(request: Request, paste_id: str, password: Optional[str] = None):
    try:
        paste_uuid = uuid.UUID(paste_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    paste = session.execute(
        "SELECT * FROM pastes WHERE id = ?",
        [paste_uuid]
    ).one()
    
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Check if paste is expired
    if paste.expires_at and datetime.now() > paste.expires_at:
        raise HTTPException(status_code=404, detail="Paste has expired")
    
    # Check password protection
    if paste.password_hash and not password:
        return templates.TemplateResponse("password.html", {
            "request": request, 
            "paste_id": paste_id
        })
    
    if paste.password_hash and not verify_password(password, paste.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Increment views
    session.execute(
        "UPDATE pastes SET views = views + 1 WHERE id = ?",
        [paste_uuid]
    )
    
    # Get threads
    threads = session.execute(
        "SELECT * FROM threads WHERE paste_id = ? ALLOW FILTERING",
        [paste_uuid]
    )
    
    return templates.TemplateResponse("paste.html", {
        "request": request,
        "paste": paste,
        "threads": list(threads)
    })

@app.post("/api/thread")
async def create_thread(
    paste_id: str = Form(...),
    content: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    try:
        paste_uuid = uuid.UUID(paste_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Get user info
    user = session.execute(
        "SELECT id FROM users WHERE username = ? ALLOW FILTERING",
        [current_user]
    ).one()
    
    thread_id = uuid.uuid4()
    session.execute("""
        INSERT INTO threads (id, paste_id, author_id, author_username, content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [thread_id, paste_uuid, user.id, current_user, content, datetime.now()])
    
    return {"thread_id": str(thread_id)}

@app.get("/api/paste/{paste_id}/stats")
async def get_paste_stats(paste_id: str):
    try:
        paste_uuid = uuid.UUID(paste_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    paste = session.execute(
        "SELECT views FROM pastes WHERE id = ?",
        [paste_uuid]
    ).one()
    
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    return {"views": paste.views}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: str = Depends(get_current_user)):
    # Get user's pastes
    user = session.execute(
        "SELECT id FROM users WHERE username = ? ALLOW FILTERING",
        [current_user]
    ).one()
    
    pastes = session.execute(
        "SELECT * FROM pastes WHERE author_id = ? ALLOW FILTERING",
        [user.id]
    )
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "pastes": list(pastes)
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
