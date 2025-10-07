# main.py - FastAPI Backend with WebSocket Support
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta
import json

# Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"  # CHANGE THIS!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

app = FastAPI()

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  username TEXT NOT NULL,
                  message TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

init_db()

# Pydantic models
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    message: str

# Connection Manager for WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        print(f"User {username} connected. Total users: {len(self.active_connections)}")
    
    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            print(f"User {username} disconnected. Total users: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        disconnected = []
        for username, connection in self.active_connections.items():
            try:
                await connection.send_json(message)
            except:
                disconnected.append(username)
        
        # Clean up disconnected users
        for username in disconnected:
            self.disconnect(username)

manager = ConnectionManager()

# Auth functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("username")
    except:
        return None

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return username

# REST API Endpoints
@app.post("/api/register")
async def register(user: UserRegister):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    try:
        password_hash = hash_password(user.password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  (user.username, password_hash))
        conn.commit()
        
        token = create_access_token({"username": user.username})
        return {"token": token, "username": user.username}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

@app.post("/api/login")
async def login(user: UserLogin):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    c.execute("SELECT id, username, password_hash FROM users WHERE username = ?",
              (user.username,))
    result = c.fetchone()
    conn.close()
    
    if result is None or not verify_password(user.password, result[2]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"username": result[1]})
    return {"token": token, "username": result[1]}

@app.get("/api/messages")
async def get_messages(username: str = Depends(get_current_user)):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    c.execute("""SELECT username, message, timestamp 
                 FROM messages 
                 ORDER BY timestamp DESC 
                 LIMIT 100""")
    messages = c.fetchall()
    conn.close()
    
    return [
        {
            "username": msg[0],
            "message": msg[1],
            "timestamp": msg[2]
        }
        for msg in reversed(messages)
    ]

@app.get("/api/online-users")
async def get_online_users(username: str = Depends(get_current_user)):
    return {"users": list(manager.active_connections.keys())}

# WebSocket endpoint
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    username = verify_token(token)
    
    if username is None:
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, username)
    
    # Notify others that user joined
    await manager.broadcast({
        "type": "user_joined",
        "username": username,
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Save message to database
            conn = sqlite3.connect('chat.db')
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_id = c.fetchone()[0]
            
            c.execute("INSERT INTO messages (user_id, username, message) VALUES (?, ?, ?)",
                      (user_id, username, message_data['message']))
            conn.commit()
            
            c.execute("SELECT timestamp FROM messages WHERE id = last_insert_rowid()")
            timestamp = c.fetchone()[0]
            conn.close()
            
            # Broadcast message to all connected clients
            await manager.broadcast({
                "type": "message",
                "username": username,
                "message": message_data['message'],
                "timestamp": timestamp
            })
    
    except WebSocketDisconnect:
        manager.disconnect(username)
        await manager.broadcast({
            "type": "user_left",
            "username": username,
            "timestamp": datetime.now().isoformat()
        })

# Serve static files (frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_index():
    return FileResponse('static/index.html')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)