from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import json
from typing import Optional, List, Dict, Any
import os
from decouple import config
import time
import logging
import subprocess
import tempfile
import shutil

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Lunox Clone - Code Sharing Platform")

# Security
SECRET_KEY = config("SECRET_KEY", default="your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Templates
templates = Jinja2Templates(directory="templates")

# Create data directories
os.makedirs("data/users", exist_ok=True)
os.makedirs("data/codes", exist_ok=True)
os.makedirs("data/threads", exist_ok=True)

# JSON Database Functions
def load_json_file(filepath: str) -> Dict[str, Any]:
    """Load JSON file, return empty dict if file doesn't exist"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_json_file(filepath: str, data: Dict[str, Any]) -> None:
    """Save data to JSON file"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user data by username"""
    filepath = f"data/users/{username}.json"
    user_data = load_json_file(filepath)
    return user_data if user_data else None

def save_user(username: str, user_data: Dict[str, Any]) -> None:
    """Save user data"""
    filepath = f"data/users/{username}.json"
    save_json_file(filepath, user_data)

def get_code_by_id(code_id: str) -> Optional[Dict[str, Any]]:
    """Get code data by ID"""
    filepath = f"data/codes/{code_id}.json"
    code_data = load_json_file(filepath)
    return code_data if code_data else None

def save_code(code_id: str, code_data: Dict[str, Any]) -> None:
    """Save code data"""
    filepath = f"data/codes/{code_id}.json"
    save_json_file(filepath, code_data)

def get_user_codes(username: str) -> List[Dict[str, Any]]:
    """Get all codes by user"""
    codes = []
    if os.path.exists("data/codes"):
        for filename in os.listdir("data/codes"):
            if filename.endswith(".json"):
                code_data = load_json_file(f"data/codes/{filename}")
                if code_data.get("author_username") == username:
                    codes.append(code_data)
    return sorted(codes, key=lambda x: x.get("created_at", ""), reverse=True)

def get_threads_by_code_id(code_id: str) -> List[Dict[str, Any]]:
    """Get all threads for a code"""
    filepath = f"data/threads/{code_id}.json"
    threads_data = load_json_file(filepath)
    return threads_data.get("threads", [])

def save_thread(code_id: str, thread_data: Dict[str, Any]) -> None:
    """Save thread to code"""
    filepath = f"data/threads/{code_id}.json"
    threads_data = load_json_file(filepath)
    if "threads" not in threads_data:
        threads_data["threads"] = []
    threads_data["threads"].append(thread_data)
    save_json_file(filepath, threads_data)

# Code execution functions
def execute_code(code: str, language: str) -> Dict[str, Any]:
    """Execute code and return result"""
    try:
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            if language.lower() == "python":
                file_path = os.path.join(temp_dir, "code.py")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                
                # Execute Python code
                result = subprocess.run(
                    ["python", file_path],
                    capture_output=True,
                    text=True,
                    timeout=10,  # 10 second timeout
                    cwd=temp_dir
                )
                
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr,
                    "return_code": result.returncode
                }
                
            elif language.lower() == "javascript":
                file_path = os.path.join(temp_dir, "code.js")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                
                # Execute JavaScript code with Node.js
                result = subprocess.run(
                    ["node", file_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=temp_dir
                )
                
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr,
                    "return_code": result.returncode
                }
                
            elif language.lower() in ["bash", "shell"]:
                file_path = os.path.join(temp_dir, "code.sh")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                
                # Make executable and run
                os.chmod(file_path, 0o755)
                result = subprocess.run(
                    ["bash", file_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=temp_dir
                )
                
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr,
                    "return_code": result.returncode
                }
            
            else:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Language '{language}' is not supported for execution",
                    "return_code": -1
                }
                
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": "Code execution timed out (10 seconds limit)",
            "return_code": -1
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": f"Execution error: {str(e)}",
            "return_code": -1
        }

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

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "json_files"}

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
    existing_user = get_user_by_username(username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user_id = str(uuid.uuid4())
    password_hash = get_password_hash(password)
    
    user_data = {
        "id": user_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "created_at": datetime.now().isoformat(),
        "badges": ["newcomer"]
    }
    
    save_user(username, user_data)
    
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
    user = get_user_by_username(username)
    
    if not user or not verify_password(password, user["password_hash"]):
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
    paste_id = str(uuid.uuid4())
    password_hash = get_password_hash(password) if password else None
    expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat() if expires_hours > 0 else None
    
    # Get user info
    user = get_user_by_username(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    paste_data = {
        "id": paste_id,
        "title": title,
        "content": content,
        "language": language,
        "author_id": user["id"],
        "author_username": current_user,
        "is_private": is_private,
        "password_hash": password_hash,
        "views": 0,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires_at
    }
    
    save_code(paste_id, paste_data)
    
    return {"paste_id": paste_id}

@app.get("/paste/{paste_id}", response_class=HTMLResponse)
async def view_paste(
    request: Request, 
    paste_id: str, 
    password: Optional[str] = None
):
    paste = get_code_by_id(paste_id)
    
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Check if paste is expired
    if paste.get("expires_at"):
        expires_at = datetime.fromisoformat(paste["expires_at"])
        if datetime.now() > expires_at:
            raise HTTPException(status_code=404, detail="Paste has expired")
    
    # Check password protection
    if paste.get("password_hash") and not password:
        return templates.TemplateResponse("password.html", {
            "request": request, 
            "paste_id": paste_id
        })
    
    if paste.get("password_hash") and not verify_password(password, paste["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Increment views
    paste["views"] = paste.get("views", 0) + 1
    save_code(paste_id, paste)
    
    # Get threads
    threads = get_threads_by_code_id(paste_id)
    
    return templates.TemplateResponse("paste.html", {
        "request": request,
        "paste": paste,
        "threads": threads
    })

@app.post("/api/thread")
async def create_thread(
    paste_id: str = Form(...),
    content: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    # Check if paste exists
    paste = get_code_by_id(paste_id)
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Get user info
    user = get_user_by_username(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    thread_data = {
        "id": str(uuid.uuid4()),
        "paste_id": paste_id,
        "author_id": user["id"],
        "author_username": current_user,
        "content": content,
        "created_at": datetime.now().isoformat()
    }
    
    save_thread(paste_id, thread_data)
    
    return {"thread_id": thread_data["id"]}

@app.post("/api/execute")
async def execute_code_endpoint(
    code: str = Form(...),
    language: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    """Execute code and return result"""
    result = execute_code(code, language)
    return result

@app.get("/api/paste/{paste_id}/stats")
async def get_paste_stats(paste_id: str):
    paste = get_code_by_id(paste_id)
    
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    return {"views": paste.get("views", 0)}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request, 
    current_user: str = Depends(get_current_user)
):
    # Get user's pastes
    pastes = get_user_codes(current_user)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "pastes": pastes
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
