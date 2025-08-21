from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
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
from collections import defaultdict
import httpx
from urllib.parse import urlencode
import base64
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set
import asyncio
import json as json_lib

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CodeShare - Code Sharing Platform")

# Security
SECRET_KEY = config("SECRET_KEY", default="your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

GOOGLE_CLIENT_ID = "-"
GOOGLE_CLIENT_SECRET = "-"
GOOGLE_REDIRECT_URI = "https://codeshare.nauval.site/auth/google/callback"


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

templates = Jinja2Templates(directory="templates")

os.makedirs("data/users", exist_ok=True)
os.makedirs("data/codes", exist_ok=True)
os.makedirs("data/threads", exist_ok=True)
os.makedirs("data/notifications", exist_ok=True)
os.makedirs("data/profile_pictures", exist_ok=True)

app.mount("/profile_pictures", StaticFiles(directory="data/profile_pictures"), name="profile_pictures")

def load_json_file(filepath: str) -> Dict[str, Any]:
    """Load JSON file, return empty dict if file doesn't exist"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_json_file(filepath: str, data: Dict[str, Any]) -> None:
    """Save data to JSON file"""
    directory = os.path.dirname(filepath)
    if directory:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"[File Debug] Directory created/verified: {directory}")
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"[File Debug] Successfully saved file: {filepath}")
        
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            logger.info(f"[File Debug] File verified - size: {file_size} bytes")
        else:
            logger.error(f"[File Debug] File not found after save: {filepath}")
            
    except Exception as e:
        logger.error(f"[File Debug] Error saving file {filepath}: {str(e)}")
        raise

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

def save_uploaded_file(file: UploadFile) -> str:
    """Save uploaded file and return content"""
    try:
        content = file.file.read().decode('utf-8')
        return content
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be text-based")

def get_public_codes(limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent public codes from all users"""
    codes = []
    if os.path.exists("data/codes"):
        for filename in os.listdir("data/codes"):
            if filename.endswith(".json"):
                code_data = load_json_file(f"data/codes/{filename}")
                # Only include public codes (not private and no password)
                if not code_data.get("is_private", False) and not code_data.get("password_hash"):
                    codes.append(code_data)
    
    # Sort by created_at and limit results
    sorted_codes = sorted(codes, key=lambda x: x.get("created_at", ""), reverse=True)
    return sorted_codes[:limit]

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

# Badge tier system functions
def calculate_user_badges(username: str) -> List[str]:
    """Calculate badges based on user activity"""
    user = get_user_by_username(username)
    if not user:
        return ["newcomer"]
    
    admin_badges = []
    if user.get("is_admin", False):
        admin_badges.append("admin")
    if user.get("verified_by_admin", False):
        admin_badges.append("verified")
    
    user_codes = get_user_codes(username)
    total_pastes = len(user_codes)
    total_views = sum(paste.get("views", 0) for paste in user_codes)
    
    badges = admin_badges.copy()
    
    # Badge tiers based on activity (don't override admin badges)
    if total_pastes >= 50 and total_views >= 10000:
        if "legend" not in badges:
            badges.append("legend")
    elif total_pastes >= 25 and total_views >= 5000:
        if "expert" not in badges:
            badges.append("expert")
    elif total_pastes >= 15 and total_views >= 2000:
        if "pro" not in badges:
            badges.append("pro")
    elif total_pastes >= 8 and total_views >= 500:
        if "verified" not in badges:
            badges.append("verified")
    elif total_pastes >= 3 and total_views >= 100:
        if "member" not in badges:
            badges.append("member")
    else:
        if not admin_badges:  # Only add newcomer if no admin badges
            badges.append("newcomer")
    
    # Special badges
    if total_views >= 1000 and "popular" not in badges:
        badges.append("popular")
    if total_pastes >= 10 and "prolific" not in badges:
        badges.append("prolific")
    
    return badges

def update_user_badges(username: str) -> None:
    """Update user badges based on current activity"""
    user = get_user_by_username(username)
    if user:
        new_badges = calculate_user_badges(username)
        user["badges"] = new_badges
        save_user(username, user)

def get_badge_info(badge: str) -> Dict[str, str]:
    """Get badge display information"""
    badge_info = {
        "newcomer": {"name": "Newcomer", "color": "bg-gray-500", "icon": "🌱", "verified": False},
        "member": {"name": "Member", "color": "bg-green-500", "icon": "👤", "verified": False},
        "verified": {"name": "Verified", "color": "bg-blue-500", "icon": "✅", "verified": True},
        "pro": {"name": "Pro", "color": "bg-purple-500", "icon": "⭐", "verified": False},
        "expert": {"name": "Expert", "color": "bg-orange-500", "icon": "🏆", "verified": False},
        "legend": {"name": "Legend", "color": "bg-red-500", "icon": "👑", "verified": False},
        "popular": {"name": "Popular", "color": "bg-pink-500", "icon": "🔥", "verified": False},
        "prolific": {"name": "Prolific", "color": "bg-indigo-500", "icon": "📝", "verified": False},
        "admin": {"name": "Admin", "color": "bg-red-600", "icon": "👨‍💼", "verified": True}
    }
    return badge_info.get(badge, {"name": badge.title(), "color": "bg-gray-500", "icon": "🏅", "verified": False})

# Admin user management functions
def create_admin_user():
    """Create default admin user if not exists"""
    admin_username = "admin"
    admin_user = get_user_by_username(admin_username)
    
    if not admin_user:
        admin_data = {
            "id": str(uuid.uuid4()),
            "username": admin_username,
            "email": "admin@codeshare.com",
            "password_hash": get_password_hash("admin123"),  # Default password
            "created_at": datetime.now().isoformat(),
            "badges": ["admin", "verified", "legend"],
            "is_admin": True,
            "verified_by_admin": True
        }
        save_user(admin_username, admin_data)
        logger.info("Default admin user created")

def is_admin_user(username: str) -> bool:
    """Check if user is admin"""
    user = get_user_by_username(username)
    return user and user.get("is_admin", False)

def get_all_users() -> List[Dict[str, Any]]:
    """Get all users (admin only)"""
    users = []
    if os.path.exists("data/users"):
        for filename in os.listdir("data/users"):
            if filename.endswith(".json"):
                user_data = load_json_file(f"data/users/{filename}")
                if user_data:
                    # Remove sensitive data
                    safe_user = {
                        "username": user_data.get("username"),
                        "email": user_data.get("email"),
                        "created_at": user_data.get("created_at"),
                        "badges": user_data.get("badges", []),
                        "is_admin": user_data.get("is_admin", False),
                        "verified_by_admin": user_data.get("verified_by_admin", False),
                        "profile_picture": user_data.get("profile_picture")
                    }
                    users.append(safe_user)
    return sorted(users, key=lambda x: x.get("created_at", ""), reverse=True)

def verify_user_by_admin(username: str, admin_username: str) -> bool:
    """Admin verifies a user"""
    if not is_admin_user(admin_username):
        return False
    
    user = get_user_by_username(username)
    if not user:
        return False
    
    user["verified_by_admin"] = True
    if "verified" not in user.get("badges", []):
        user["badges"].append("verified")
    
    save_user(username, user)
    return True

@app.post("/api/admin/promote-user")
async def promote_user_to_admin(
    username: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    """Promote a user to admin (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Promote to admin
    user["is_admin"] = True
    user["verified_by_admin"] = True
    
    # Update badges
    if "admin" not in user.get("badges", []):
        user["badges"].append("admin")
    if "verified" not in user.get("badges", []):
        user["badges"].append("verified")
    
    save_user(username, user)
    
    return {"message": f"User {username} has been promoted to admin"}

create_admin_user()

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "json_files"}


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.user_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        self.user_connections[websocket] = user_id
    
    def disconnect(self, websocket: WebSocket):
        user_id = self.user_connections.get(websocket)
        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        if websocket in self.user_connections:
            del self.user_connections[websocket]
    
    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id].copy():
                try:
                    await connection.send_text(message)
                except:
                    self.active_connections[user_id].discard(connection)
    
    async def broadcast_to_followers(self, message: str, user_id: str):
        user = get_user_by_username(user_id)
        if user and "followers" in user:
            for follower in user["followers"]:
                await self.send_personal_message(message, follower)
    
    async def broadcast_global(self, message: str):
        for user_connections in self.active_connections.values():
            for connection in user_connections.copy():
                try:
                    await connection.send_text(message)
                except:
                    user_connections.discard(connection)

manager = ConnectionManager()

def create_notification(user_id: str, notification_type: str, title: str, message: str, data: Dict = None):
    """Create a notification for a user"""
    notification = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": notification_type,
        "title": title,
        "message": message,
        "data": data or {},
        "read": False,
        "created_at": datetime.now().isoformat()
    }
    
    # Save notification to user's notification file
    notifications_file = f"data/notifications/{user_id}.json"
    os.makedirs("data/notifications", exist_ok=True)
    
    notifications_data = load_json_file(notifications_file)
    if "notifications" not in notifications_data:
        notifications_data["notifications"] = []
    
    notifications_data["notifications"].insert(0, notification)
    # Keep only last 50 notifications
    notifications_data["notifications"] = notifications_data["notifications"][:50]
    
    save_json_file(notifications_file, notifications_data)
    return notification

async def send_real_time_notification(user_id: str, notification: Dict):
    """Send real-time notification via WebSocket"""
    message = json_lib.dumps({
        "type": "notification",
        "data": notification
    })
    await manager.send_personal_message(message, user_id)

def get_feed_for_user(username: str, page: int = 1, limit: int = 10) -> Dict[str, Any]:
    """Get feed of recent pastes from followed users"""
    user = get_user_by_username(username)
    if not user:
        return {"pastes": [], "total": 0, "page": page, "pages": 0}
    
    following = user.get("following", [])
    if not following:
        return {"pastes": [], "total": 0, "page": page, "pages": 0}
    
    feed_pastes = []
    
    if os.path.exists("data/codes"):
        for filename in os.listdir("data/codes"):
            if filename.endswith(".json"):
                paste_data = load_json_file(f"data/codes/{filename}")
                if paste_data and not paste_data.get("is_private", False):
                    author = paste_data.get("author_username", "")
                    if author in following:
                        # Add author badge details
                        author_user = get_user_by_username(author)
                        if author_user:
                            paste_data["author_badge_details"] = get_badge_info(author_user.get("badges", []))
                            paste_data["author_is_verified"] = author_user.get("verified_by_admin", False)
                            paste_data["author_is_admin"] = author_user.get("is_admin", False)
                        
                        feed_pastes.append(paste_data)
    
    # Sort by creation date (newest first)
    feed_pastes.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    
    # Pagination
    total = len(feed_pastes)
    pages = (total + limit - 1) // limit
    start = (page - 1) * limit
    end = start + limit
    
    return {
        "pastes": feed_pastes[start:end],
        "total": total,
        "page": page,
        "pages": pages
    }

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

async def get_google_user_info(access_token: str) -> Dict[str, Any]:
    """Get user info from Google using access token"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise HTTPException(status_code=400, detail="Failed to get user info from Google")

async def exchange_code_for_token(code: str) -> str:
    """Exchange authorization code for access token"""
    async with httpx.AsyncClient() as client:
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI,
        }
        response = await client.post("https://oauth2.googleapis.com/token", data=data)
        if response.status_code == 200:
            token_data = response.json()
            return token_data["access_token"]
        else:
            raise HTTPException(status_code=400, detail="Failed to exchange code for token")

def create_user_from_google(google_user: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new user from Google OAuth data"""
    base_username = google_user["email"].split("@")[0]
    username = base_username
    
    # Ensure username is unique
    counter = 1
    while get_user_by_username(username):
        username = f"{base_username}{counter}"
        counter += 1
    
    logger.info(f"[User Debug] Creating user with username: {username}")
    
    user_id = str(uuid.uuid4())
    user_data = {
        "id": user_id,
        "username": username,
        "email": google_user["email"],
        "google_id": google_user["id"],
        "name": google_user.get("name", ""),
        "picture": google_user.get("picture", ""),
        "created_at": datetime.now().isoformat(),
        "badges": ["newcomer", "google_user"],
        "is_admin": False,
        "verified_by_admin": True,  # Auto-verify Google users
        "auth_provider": "google"
    }
    
    logger.info(f"[User Debug] User data prepared: {json.dumps(user_data, indent=2)}")
    
    try:
        save_user(username, user_data)
        logger.info(f"[User Debug] User {username} saved successfully")
        
        saved_user = get_user_by_username(username)
        if saved_user:
            logger.info(f"[User Debug] Verification: User {username} found in database")
        else:
            logger.error(f"[User Debug] Verification failed: User {username} not found after save!")
            
    except Exception as e:
        logger.error(f"[User Debug] Error saving user {username}: {str(e)}")
        raise
    
    return user_data

@app.get("/auth/google")
async def google_login():
    """Redirect to Google OAuth"""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": "openid email profile",
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent"
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)

@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str = None, error: str = None):
    """Handle Google OAuth callback"""
    logger.info(f"[OAuth Debug] Callback received - code: {'present' if code else 'missing'}, error: {error}")
    
    if error:
        logger.error(f"[OAuth Debug] OAuth error received: {error}")
        return RedirectResponse(url="/login?error=access_denied")
    
    if not code:
        logger.error("[OAuth Debug] No authorization code received")
        return RedirectResponse(url="/login?error=no_code")
    
    try:
        
        logger.info("[OAuth Debug] Exchanging code for access token...")
        access_token = await exchange_code_for_token(code)
        logger.info("[OAuth Debug] Access token obtained successfully")
        
        
        logger.info("[OAuth Debug] Getting user info from Google...")
        google_user = await get_google_user_info(access_token)
        logger.info(f"[OAuth Debug] Google user info: email={google_user.get('email')}, id={google_user.get('id')}")
        
        
        
        existing_user = None
        logger.info("[OAuth Debug] Checking for existing user...")
        for filename in os.listdir("data/users"):
            if filename.endswith(".json"):
                user_data = load_json_file(f"data/users/{filename}")
                if user_data and (
                    user_data.get("google_id") == google_user["id"] or
                    user_data.get("email") == google_user["email"]
                ):
                    existing_user = user_data
                    logger.info(f"[OAuth Debug] Found existing user: {user_data.get('username')}")
                    break
        
        if existing_user:
            
            
            if not existing_user.get("google_id"):
                logger.info("[OAuth Debug] Updating existing user with Google info...")
                existing_user["google_id"] = google_user["id"]
                existing_user["picture"] = google_user.get("picture", "")
                existing_user["auth_provider"] = "google"
                save_user(existing_user["username"], existing_user)
                logger.info(f"[OAuth Debug] Updated user {existing_user['username']} saved successfully")
            username = existing_user["username"]
        else:
            # Create new user
            logger.info("[OAuth Debug] Creating new user from Google data...")
            user_data = create_user_from_google(google_user)
            username = user_data["username"]
            logger.info(f"[OAuth Debug] New user created: {username}")
            
            
            
            saved_user = get_user_by_username(username)
            if saved_user:
                logger.info(f"[OAuth Debug] User {username} successfully saved to data/users/{username}.json")
            else:
                logger.error(f"[OAuth Debug] Failed to save user {username} to database!")
        
        # Create JWT token
        logger.info(f"[OAuth Debug] Creating JWT token for user: {username}")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        jwt_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        logger.info("[OAuth Debug] JWT token created successfully")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Successful</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background-color: #f5f5f5;
                }}
                .container {{
                    text-align: center;
                    background: white;
                    padding: 2rem;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .spinner {{
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #3498db;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 0 auto 1rem;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="spinner"></div>
                <h2>Login Berhasil!</h2>
                <p>Mengarahkan ke dashboard...</p>
            </div>
            <script>
                // Store token in localStorage
                localStorage.setItem('token', '{jwt_token}');
                
                // Redirect to dashboard after short delay
                setTimeout(function() {{
                    window.location.href = '/dashboard';
                }}, 1500);
            </script>
        </body>
        </html>
        """
        
        logger.info("[OAuth Debug] Returning inline HTML response with token")
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        logger.error(f"[OAuth Debug] Google OAuth error: {str(e)}")
        logger.error(f"[OAuth Debug] Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"[OAuth Debug] Traceback: {traceback.format_exc()}")
        return RedirectResponse(url="/login?error=oauth_failed")

# @app.get("/auth/success")
# async def auth_success(request: Request):
#     """OAuth success page that handles token storage"""
#     return templates.TemplateResponse("auth_success.html", {"request": request})

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
        "badges": ["newcomer"],
        "is_admin": False,
        "verified_by_admin": False,
        "auth_provider": "local",
        "profile_picture": None
    }
    
    save_user(username, user_data)
    
    
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

@app.get("/edit/{paste_id}", response_class=HTMLResponse)
async def edit_paste_page(request: Request, paste_id: str):
    """Serve the edit page for a specific paste"""
    return templates.TemplateResponse("edit.html", {
        "request": request,
        "paste_id": paste_id
    })

@app.post("/api/paste")
async def create_paste(
    title: str = Form(...),
    content: str = Form(default=""),
    language: str = Form(default="text"),
    is_private: bool = Form(default=False),
    password: Optional[str] = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
    current_user: str = Depends(get_current_user)
):
    paste_id = str(uuid.uuid4())
    password_hash = get_password_hash(password) if password else None
    
    # Handle file upload
    final_content = content
    if file and file.filename:
        try:
            file_content = save_uploaded_file(file)
            final_content = file_content if not content else content + "\n\n" + file_content

            if language == "text" and file.filename:
                ext = file.filename.split('.')[-1].lower()
                language_map = {
                    # Bahasa pemrograman populer
                    'py': 'python',
                    'js': 'javascript',
                    'ts': 'typescript',
                    'html': 'html',
                    'htm': 'html',
                    'css': 'css',
                    'java': 'java',
                    'cpp': 'cpp',
                    'c': 'c',
                    'cs': 'csharp',
                    'rb': 'ruby',
                    'php': 'php',
                    'go': 'go',
                    'rs': 'rust',
                    'kt': 'kotlin',
                    'swift': 'swift',
                    'scala': 'scala',
                    'dart': 'dart',

                    # Data & config
                    'sql': 'sql',
                    'json': 'json',
                    'xml': 'xml',
                    'yml': 'yaml',
                    'yaml': 'yaml',
                    'toml': 'toml',
                    'ini': 'ini',
                    'cfg': 'ini',
                    'env': 'dotenv',

                    # Shell & scripting
                    'sh': 'bash',
                    'bash': 'bash',
                    'ps1': 'powershell',
                    'bat': 'batch',
                    'cmd': 'batch',

                    # Markup & docs
                    'md': 'markdown',
                    'markdown': 'markdown',
                    'rst': 'rst',
                    'tex': 'latex',
                    'latex': 'latex',

                    # Web & template
                    'vue': 'vue',
                    'svelte': 'svelte',
                    'jsx': 'jsx',
                    'tsx': 'tsx',
                    'ejs': 'ejs',
                    'twig': 'twig',
                    'jinja': 'jinja',

                    # Tambahan lain
                    'pl': 'perl',
                    'lua': 'lua',
                    'r': 'r',
                    'erl': 'erlang',
                    'ex': 'elixir',
                    'clj': 'clojure',
                    'hs': 'haskell',
                    'ml': 'ocaml'
                }

                language = language_map.get(ext, 'text')
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")

    
    # Get user info
    user = get_user_by_username(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    paste_data = {
        "id": paste_id,
        "title": title,
        "content": final_content,
        "language": language,
        "author_id": user["id"],
        "author_username": current_user,
        "is_private": is_private,
        "password_hash": password_hash,
        "views": 0,
        "created_at": datetime.now().isoformat(),
        "expires_at": None
    }
    
    save_code(paste_id, paste_data)
    
    update_user_badges(current_user)
    
    if not is_private:
        
        user = get_user_by_username(current_user)
        if user and "followers" in user:
            for follower in user["followers"]:
                notification = create_notification(
                    follower,
                    "new_paste",
                    "New Paste from " + current_user,
                    f"{current_user} shared a new {language} paste: {title}",
                    {"paste_id": paste_id, "author": current_user}
                )
                await send_real_time_notification(follower, notification)
        
        
        
        await manager.broadcast_global(json_lib.dumps({
            "type": "new_paste",
            "paste_id": paste_id,
            "title": title,
            "author": current_user,
            "language": language
        }))
    
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
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page - authentication handled client-side"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/dashboard")
async def api_dashboard(current_user: str = Depends(get_current_user)):
    """API endpoint for dashboard data"""
    user_data = get_user_by_username(current_user)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    # Ambil semua paste milik user
    user_pastes = []
    for filename in os.listdir("data/codes"):
        if filename.endswith(".json"):
            paste_id = filename[:-5]
            paste = get_code_by_id(paste_id)
            if paste and paste.get("author_username") == current_user:
                user_pastes.append({
                    "id": paste["id"],
                    "title": paste["title"],
                    "language": paste["language"],
                    "views": paste.get("views", 0),
                    "created_at": paste["created_at"]
                })

    return {
        "user": {
            "username": user_data["username"],
            "email": user_data["email"],
            "badges": user_data.get("badges", []),
            "verified_by_admin": user_data.get("verified_by_admin", False),
            "is_admin": user_data.get("is_admin", False),
            "profile_picture": user_data.get("profile_picture")
        },
        "pastes": user_pastes,
        "stats": {
            "total_pastes": len(user_pastes),
            "total_views": sum(paste.get("views", 0) for paste in user_pastes)
        }
    }






@app.get("/{paste_id}", response_class=HTMLResponse)
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
    
    referer = request.headers.get("referer", "")
    session_id = request.cookies.get("session_id")
    
    # Don't count views from edit page or same session within 5 minutes
    should_count_view = True
    if "/edit/" in referer:
        should_count_view = False
    elif session_id:
        last_view_key = f"last_view_{paste_id}_{session_id}"
        last_view = paste.get(last_view_key)
        if last_view:
            last_view_time = datetime.fromisoformat(last_view)
            if (datetime.now() - last_view_time).seconds < 300:  # 5 minutes
                should_count_view = False
    
    if should_count_view:
        paste["views"] = paste.get("views", 0) + 1
        if session_id:
            paste[f"last_view_{paste_id}_{session_id}"] = datetime.now().isoformat()
        save_code(paste_id, paste)
        
        await manager.broadcast_global(json_lib.dumps({
            "type": "view_update",
            "paste_id": paste_id,
            "views": paste["views"]
        }))
    
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

@app.post("/api/run-code")
async def execute_code_endpoint(
    request: Request
):
    """Execute code and return result"""
    try:
        data = await request.json()
        code = data.get("code", "")
        language = data.get("language", "text")
        
        if not code.strip():
            raise HTTPException(status_code=400, detail="No code provided")
        
        result = execute_code(code, language)
        
        return {
            "output": result["output"] if result["success"] else result["error"],
            "error": not result["success"]
        }
    except Exception as e:
        return {"output": f"Error: {str(e)}", "error": True}

@app.get("/api/paste/{paste_id}/stats")
async def get_paste_stats(paste_id: str):
    paste = get_code_by_id(paste_id)
    
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    return {"views": paste.get("views", 0)}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page - authentication handled client-side"""
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username and is_admin_user(username):
                return templates.TemplateResponse("dashboardadmin.html", {"request": request})
        except JWTError:
            pass
    
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/user/{username}")
async def view_user_profile(username: str, request: Request):
    """View user profile page"""
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's public pastes
    user_codes = get_user_codes(username)
    
    # Update user badges
    update_user_badges(username)
    updated_user = get_user_by_username(username)
    
    # Get badge details
    badge_details = []
    for badge in updated_user.get("badges", []):
        badge_info = get_badge_info(badge)
        badge_details.append({
            "name": badge,
            "display_name": badge_info["name"],
            "color": badge_info["color"],
            "icon": badge_info["icon"],
            "verified": badge_info["verified"]
        })
    
    # Get current user for authentication check
    current_user = None
    try:
        current_user = get_current_user_from_request(request)
    except:
        pass
    
    return templates.TemplateResponse("user_profile.html", {
        "request": request,
        "user": {
            "username": username,
            "badges": updated_user.get("badges", []),
            "badge_details": badge_details,
            "created_at": updated_user.get("created_at"),
            "is_admin": updated_user.get("is_admin", False),
            "verified_by_admin": updated_user.get("verified_by_admin", False),
            "profile_picture": updated_user.get("profile_picture")
        },
        "pastes": user_codes,
        "current_user": current_user,
        "is_current_user_admin": is_admin_user(current_user) if current_user else False
    })

@app.get("/users", response_class=HTMLResponse)
async def view_all_users(request: Request):
    """View all users page"""
    # Get current user for authentication check
    current_user = None
    try:
        current_user = get_current_user_from_request(request)
    except:
        pass
    
    # Get all users
    users = get_all_users()
    
    # Update badges for all users
    for user in users:
        update_user_badges(user["username"])
    
    # Get updated users with badge details
    updated_users = []
    for user in users:
        updated_user = get_user_by_username(user["username"])
        badge_details = []
        for badge in updated_user.get("badges", []):
            badge_info = get_badge_info(badge)
            badge_details.append({
                "name": badge,
                "display_name": badge_info["name"],
                "color": badge_info["color"],
                "icon": badge_info["icon"],
                "verified": badge_info["verified"]
            })
        
        updated_users.append({
            "username": user["username"],
            "email": user["email"],
            "created_at": user["created_at"],
            "badges": updated_user.get("badges", []),
            "badge_details": badge_details,
            "is_admin": updated_user.get("is_admin", False),
            "verified_by_admin": updated_user.get("verified_by_admin", False),
            "profile_picture": updated_user.get("profile_picture"),
            "paste_count": len(get_user_codes(user["username"]))
        })
    
    return templates.TemplateResponse("users.html", {
        "request": request,
        "users": updated_users,
        "current_user": current_user,
        "is_current_user_admin": is_admin_user(current_user) if current_user else False
    })

edit_rate_limit = defaultdict(list)

@app.put("/api/paste/{paste_id}")
async def edit_paste(
    paste_id: str,
    title: str = Form(...),
    content: str = Form(...),
    language: str = Form(default="text"),
    is_private: bool = Form(default=False),
    password: Optional[str] = Form(default=None),
    current_user: str = Depends(get_current_user)
):
    """Edit an existing paste - only author can edit"""
    current_time = time.time()
    user_edits = edit_rate_limit[current_user]
    
    # Remove edits older than 1 minute
    user_edits[:] = [edit_time for edit_time in user_edits if current_time - edit_time < 60]
    
    if len(user_edits) >= 5:
        raise HTTPException(status_code=429, detail="Too many edit requests. Please wait a moment.")
    
    user_edits.append(current_time)
    
    # Get existing paste
    paste = get_code_by_id(paste_id)
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Check if current user is the author or admin
    if paste.get("author_username") != current_user and not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="You can only edit your own pastes")
    
    # Update paste data
    paste["title"] = title
    paste["content"] = content
    paste["language"] = language
    paste["is_private"] = is_private
    paste["password_hash"] = get_password_hash(password) if password else None
    paste["updated_at"] = datetime.now().isoformat()
    
    # Save updated paste
    save_code(paste_id, paste)
    
    return {"message": "Paste updated successfully", "paste_id": paste_id}

@app.delete("/api/paste/{paste_id}")
async def delete_paste(
    paste_id: str,
    current_user: str = Depends(get_current_user)
):
    """Delete a paste - only author can delete"""
    # Get existing paste
    paste = get_code_by_id(paste_id)
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Check if current user is the author
    if paste.get("author_username") != current_user:
        raise HTTPException(status_code=403, detail="You can only delete your own pastes")
    
    # Delete the paste file
    paste_filepath = f"data/codes/{paste_id}.json"
    try:
        if os.path.exists(paste_filepath):
            os.remove(paste_filepath)
        
        # Also delete associated threads if they exist
        threads_filepath = f"data/threads/{paste_id}.json"
        if os.path.exists(threads_filepath):
            os.remove(threads_filepath)
            
        # Update user badges after deletion
        update_user_badges(current_user)
        
        return {"message": "Paste deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting paste: {str(e)}")

@app.get("/api/paste/{paste_id}/edit")
async def get_paste_for_edit(
    paste_id: str,
    current_user: str = Depends(get_current_user)
):
    """Get paste data for editing - only author can access"""
    paste = get_code_by_id(paste_id)
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Check if current user is the author
    if paste.get("author_username") != current_user:
        raise HTTPException(status_code=403, detail="You can only edit your own pastes")
    
    # Return paste data without sensitive information
    return {
        "id": paste["id"],
        "title": paste["title"],
        "content": paste["content"],
        "language": paste["language"],
        "is_private": paste.get("is_private", False),
        "has_password": bool(paste.get("password_hash"))
    }

@app.get("/api/public-pastes")
async def get_public_pastes(limit: int = 10):
    """Get recent public pastes from all users"""
    try:
        public_pastes = get_public_codes(limit)
        return {"pastes": public_pastes}
    except Exception as e:
        logger.error(f"Error getting public pastes: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving public pastes")

# Admin-only endpoints
@app.get("/api/admin/users")
async def get_users_admin(current_user: str = Depends(get_current_user)):
    """Get all users (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = get_all_users()
    return {"users": users}

@app.post("/api/admin/verify-user")
async def verify_user_endpoint(
    username: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    """Verify a user (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    success = verify_user_by_admin(username, current_user)
    if not success:
        raise HTTPException(status_code=404, detail="User not found or already verified")
    
    return {"message": f"User {username} has been verified"}

@app.get("/api/admin/stats")
async def get_admin_stats(current_user: str = Depends(get_current_user)):
    """Get platform statistics (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Count users
    total_users = len(get_all_users())
    
    # Count pastes
    total_pastes = 0
    total_views = 0
    if os.path.exists("data/codes"):
        for filename in os.listdir("data/codes"):
            if filename.endswith(".json"):
                paste_data = load_json_file(f"data/codes/{filename}")
                if paste_data:
                    total_pastes += 1
                    total_views += paste_data.get("views", 0)
    
    return {
        "total_users": total_users,
        "total_pastes": total_pastes,
        "total_views": total_views
    }

# Profile editing endpoints

@app.post("/api/profile-picture")
async def upload_profile_picture(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Upload or update user's profile picture"""
    allowed_extensions = {"png", "jpg", "jpeg", "gif"}
    ext = file.filename.split(".")[-1].lower()
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Invalid image format")

    save_dir = "data/profile_pictures"
    os.makedirs(save_dir, exist_ok=True)
    file_path = f"{save_dir}/{current_user}.{ext}"

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    user = get_user_by_username(current_user)
    user["profile_picture"] = f"/profile_pictures/{current_user}.{ext}"
    save_user(current_user, user)

    return {"profile_picture": user["profile_picture"]}

@app.post("/api/profile/update")
async def update_profile(
    name: Optional[str] = Form(default=None),
    username: Optional[str] = Form(default=None),
    password: Optional[str] = Form(default=None),
    current_user: str = Depends(get_current_user)
):
    """Update user profile information"""
    user = get_user_by_username(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if new username already exists (if changing username)
    if username and username != current_user:
        existing_user = get_user_by_username(username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
    
    # Update user data
    if name:
        user["name"] = name
    
    if password:
        user["password_hash"] = get_password_hash(password)
    
    # Handle username change
    if username and username != current_user:
        # Save user with new username
        save_user(username, user)
        user["username"] = username

        # Delete old user file
        old_filepath = f"data/users/{current_user}.json"
        if os.path.exists(old_filepath):
            os.remove(old_filepath)

        # Rename profile picture if exists
        if user.get("profile_picture"):
            old_base = f"data/profile_pictures/{current_user}"
            for ext in ("png", "jpg", "jpeg", "gif"):
                old_file = f"{old_base}.{ext}"
                if os.path.exists(old_file):
                    new_file = f"data/profile_pictures/{username}.{ext}"
                    os.rename(old_file, new_file)
                    user["profile_picture"] = f"/profile_pictures/{username}.{ext}"
                    save_user(username, user)
                    break

        # Update all pastes with new username
        if os.path.exists("data/codes"):
            for filename in os.listdir("data/codes"):
                if filename.endswith(".json"):
                    paste_data = load_json_file(f"data/codes/{filename}")
                    if paste_data.get("author_username") == current_user:
                        paste_data["author_username"] = username
                        save_code(paste_data["id"], paste_data)
        
        # Create new token with new username
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        
        return {"message": "Profile updated successfully", "new_token": access_token}
    else:
        save_user(current_user, user)
        return {"message": "Profile updated successfully"}

# Admin delete paste endpoint
@app.delete("/api/admin/paste/{paste_id}")
async def admin_delete_paste(
    paste_id: str,
    current_user: str = Depends(get_current_user)
):
    """Delete any paste (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    paste = get_code_by_id(paste_id)
    if not paste:
        raise HTTPException(status_code=404, detail="Paste not found")
    
    # Delete the paste file
    paste_filepath = f"data/codes/{paste_id}.json"
    try:
        if os.path.exists(paste_filepath):
            os.remove(paste_filepath)
        
        # Also delete associated threads if they exist
        threads_filepath = f"data/threads/{paste_id}.json"
        if os.path.exists(threads_filepath):
            os.remove(threads_filepath)
        
        return {"message": "Paste deleted successfully by admin"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting paste: {str(e)}")

# Admin delete user endpoint
@app.delete("/api/admin/user/{username}")
async def admin_delete_user(
    username: str,
    current_user: str = Depends(get_current_user)
):
    """Delete a user (admin only)"""
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if username == current_user:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete user file
    user_filepath = f"data/users/{username}.json"
    try:
        if os.path.exists(user_filepath):
            os.remove(user_filepath)
        
        # Delete all user's pastes
        if os.path.exists("data/codes"):
            for filename in os.listdir("data/codes"):
                if filename.endswith(".json"):
                    paste_data = load_json_file(f"data/codes/{filename}")
                    if paste_data.get("author_username") == username:
                        paste_filepath = f"data/codes/{filename}"
                        if os.path.exists(paste_filepath):
                            os.remove(paste_filepath)
                        
                        # Delete associated threads
                        threads_filepath = f"data/threads/{paste_data['id']}.json"
                        if os.path.exists(threads_filepath):
                            os.remove(threads_filepath)
        
        return {"message": f"User {username} and all their content deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting user: {str(e)}")

@app.get("/api/search")
async def search_pastes(
    q: str = "",
    language: str = "",
    author: str = "",
    sort: str = "newest",
    page: int = 1,
    limit: int = 20
):
    """Enhanced search for pastes and users with pagination"""
    paste_results = []
    user_results = []
    
    if os.path.exists("data/codes"):
        for filename in os.listdir("data/codes"):
            if filename.endswith(".json"):
                paste_data = load_json_file(f"data/codes/{filename}")
                if paste_data and not paste_data.get("is_private", False) and not paste_data.get("password_hash"):
                    matches = True
                    
                    # Enhanced search criteria
                    if q:
                        title_match = q.lower() in paste_data.get("title", "").lower()
                        content_match = q.lower() in paste_data.get("content", "").lower()
                        author_match = q.lower() in paste_data.get("author_username", "").lower()
                        language_match = q.lower() in paste_data.get("language", "").lower()
                        
                        if not (title_match or content_match or author_match or language_match):
                            matches = False
                    
                    if language and paste_data.get("language", "").lower() != language.lower():
                        matches = False
                    
                    if author and paste_data.get("author_username", "").lower() != author.lower():
                        matches = False
                    
                    if matches:
                        # Add author badge details
                        author_badges = calculate_user_badges(paste_data.get("author_username", ""))
                        author_badge_details = []
                        for badge in author_badges:
                            badge_info = get_badge_info(badge)
                            author_badge_details.append({
                                "name": badge,
                                "display_name": badge_info["name"],
                                "color": badge_info["color"],
                                "icon": badge_info["icon"],
                                "verified": badge_info["verified"]
                            })
                        
                        # Check if author is verified
                        author_data = load_json_file(f"data/users/{paste_data.get('author_username', '')}.json")
                        author_is_verified = False
                        author_is_admin = False
                        if author_data:
                            author_is_verified = author_data.get("verified_by_admin", False) or author_data.get("is_admin", False)
                            author_is_admin = author_data.get("is_admin", False)
                        
                        paste_data["author_badge_details"] = author_badge_details
                        paste_data["author_is_verified"] = author_is_verified
                        paste_data["author_is_admin"] = author_is_admin
                        paste_data["type"] = "paste"
                        paste_results.append(paste_data)
    
    # Enhanced user search
    if q and os.path.exists("data/users"):
        for filename in os.listdir("data/users"):
            if filename.endswith(".json"):
                user_data = load_json_file(f"data/users/{filename}")
                if user_data and q.lower() in user_data.get("username", "").lower():
                    badges = calculate_user_badges(user_data["username"])
                    badge_details = []
                    for badge in badges:
                        badge_info = get_badge_info(badge)
                        badge_details.append({
                            "name": badge,
                            "display_name": badge_info["name"],
                            "color": badge_info["color"],
                            "icon": badge_info["icon"],
                            "verified": badge_info["verified"]
                        })
                    
                    # Count user's pastes
                    paste_count = 0
                    if os.path.exists("data/codes"):
                        for paste_file in os.listdir("data/codes"):
                            if paste_file.endswith(".json"):
                                paste_data = load_json_file(f"data/codes/{paste_file}")
                                if paste_data and paste_data.get("author_username") == user_data["username"]:
                                    paste_count += 1
                    
                    user_results.append({
                        "username": user_data["username"],
                        "badges": badges,
                        "badge_details": badge_details,
                        "is_verified": user_data.get("verified_by_admin", False) or user_data.get("is_admin", False),
                        "is_admin": user_data.get("is_admin", False),
                        "paste_count": paste_count,
                        "created_at": user_data.get("created_at", ""),
                        "type": "user"
                    })
    
    # Sort results
    if sort == "oldest":
        sorted_pastes = sorted(paste_results, key=lambda x: x.get("created_at", ""))
    elif sort == "most_viewed":
        sorted_pastes = sorted(paste_results, key=lambda x: x.get("views", 0), reverse=True)
    elif sort == "title":
        sorted_pastes = sorted(paste_results, key=lambda x: x.get("title", "").lower())
    else:  # newest
        sorted_pastes = sorted(paste_results, key=lambda x: x.get("created_at", ""), reverse=True)
    
    sorted_users = sorted(user_results, key=lambda x: x.get("username", ""))
    
    # Combine results for pagination
    all_results = sorted_users + sorted_pastes
    
    # Pagination
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_results = all_results[start_idx:end_idx]
    
    total_results = len(all_results)
    total_pages = (total_results + limit - 1) // limit
    
    return {
        "results": paginated_results,
        "total": total_results,
        "page": page,
        "pages": total_pages,
        "limit": limit
    }

@app.get("/api/feed")
async def get_user_feed(
    page: int = 1,
    limit: int = 10,
    current_user: str = Depends(get_current_user)
):
    """Get user's personalized feed"""
    feed_data = get_feed_for_user(current_user, page, limit)
    return feed_data

@app.get("/feed", response_class=HTMLResponse)
async def feed(request: Request):
    """Feed page - shows latest pastes from followed users"""
    return templates.TemplateResponse("feed.html", {"request": request})

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for real-time features"""
    await manager.connect(websocket, user_id)
    try:
        # Send initial connection confirmation
        await websocket.send_text(json_lib.dumps({
            "type": "connected",
            "message": "Real-time connection established"
        }))
        
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message_data = json_lib.loads(data)
            
            if message_data.get("type") == "ping":
                await websocket.send_text(json_lib.dumps({"type": "pong"}))
            elif message_data.get("type") == "view_paste":
                # Real-time view counter update
                paste_id = message_data.get("paste_id")
                if paste_id:
                    await manager.broadcast_global(json_lib.dumps({
                        "type": "paste_view_update",
                        "paste_id": paste_id,
                        "viewer": user_id
                    }))
                    
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/notifications")
async def get_notifications(current_user: str = Depends(get_current_user)):
    """Get user notifications"""
    notifications_file = f"data/notifications/{current_user}.json"
    notifications_data = load_json_file(notifications_file)
    return {"notifications": notifications_data.get("notifications", [])}

@app.post("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: str = Depends(get_current_user)):
    """Mark notification as read"""
    notifications_file = f"data/notifications/{current_user}.json"
    notifications_data = load_json_file(notifications_file)
    
    for notification in notifications_data.get("notifications", []):
        if notification["id"] == notification_id:
            notification["read"] = True
            break
    
    save_json_file(notifications_file, notifications_data)
    return {"message": "Notification marked as read"}

@app.post("/api/notifications/read-all")
async def mark_all_notifications_read(current_user: str = Depends(get_current_user)):
    """Mark all notifications as read"""
    notifications_file = f"data/notifications/{current_user}.json"
    notifications_data = load_json_file(notifications_file)
    
    for notification in notifications_data.get("notifications", []):
        notification["read"] = True
    
    save_json_file(notifications_file, notifications_data)
    return {"message": "All notifications marked as read"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
