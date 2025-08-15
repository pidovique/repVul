# Requiere: fastapi, uvicorn, pyyaml, requests
#   pip install fastapi uvicorn pyyaml requests

import os
import sqlite3
import base64
import json
import requests
import yaml  
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


DB_PATH = "techshop_api.db"
STATIC_SECRET = "secret"  

app = FastAPI(title="TechShop API (Vulnerable Demo)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          
    allow_credentials=True,       
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# Base de datos
# ------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_PATH):
        con = db(); cur = con.cursor()
        cur.executescript("""
        CREATE TABLE users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        );

        CREATE TABLE products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );

        CREATE TABLE orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            qty INTEGER,
            total REAL
        );

        INSERT INTO users(email,password,role) VALUES
          ('admin@techshop.com','admin123','admin'),
          ('cliente@test.com','123456','user');

        INSERT INTO products(name,price) VALUES
          ('Laptop Pro 14',1499.0),
          ('Mouse Inalámbrico',29.9),
          ('Teclado Mecánico',89.0);
        """)
        con.commit(); con.close()
init_db()

# ------------------------------------------------------------
# Modelos
# ------------------------------------------------------------
class LoginIn(BaseModel):
    email: str
    password: str

class RegisterIn(BaseModel):
    email: str
    password: str

class OrderIn(BaseModel):
    product_id: int
    qty: int


def set_session_cookie(resp: Response, user_id: int, email: str, role: str):
    
    payload = json.dumps({"id": user_id, "email": email, "role": role})
    raw = base64.b64encode(payload.encode()).decode()
    resp.set_cookie(
        "session",
        raw,
        httponly=False,       # permitir acceso desde JS
        secure=False,         # sin HTTPS
        samesite="none",      # permite envío cross-site
        max_age=60*60*8,
        path="/",
    )

def get_session_user(request: Request):
    c = request.cookies.get("session")
    if not c:
        return None
    try:
        data = json.loads(base64.b64decode(c.encode()).decode())
        return data
    except Exception:
        return None


@app.post("/login")
def login(inp: LoginIn, response: Response):
    con = db(); cur = con.cursor()
   
    q = f"SELECT id,email,password,role FROM users WHERE email='{inp.email}' AND password='{inp.password}'"
    row = cur.execute(q).fetchone()
    if not row:
        raise HTTPException(401, "Credenciales inválidas")
    set_session_cookie(response, row["id"], row["email"], row["role"])
    return {"message": "ok", "user": {"id": row["id"], "email": row["email"], "role": row["role"]}}


@app.post("/register")
def register(inp: RegisterIn):
    con = db(); cur = con.cursor()
    try:
        cur.execute("INSERT INTO users(email,password) VALUES(?,?)", (inp.email, inp.password))
        con.commit()
        return {"message": "user_created"}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Email ya existe")


@app.get("/products")
def products():
    con = db(); cur = con.cursor()
    rows = cur.execute("SELECT id,name,price FROM products").fetchall()
    return {"products": [dict(r) for r in rows]}


@app.get("/search")
def search(q: str = ""):
    con = db(); cur = con.cursor()
    query = f"SELECT id,name,price FROM products WHERE name LIKE '%{q}%'"  
    rows = cur.execute(query).fetchall()
    return {"query": query, "results": [dict(r) for r in rows]}


@app.post("/orders")
def create_order(inp: OrderIn, request: Request):
    user = get_session_user(request)
    if not user:
        raise HTTPException(401, "Auth requerida")
   
    con = db(); cur = con.cursor()
    row = cur.execute("SELECT price FROM products WHERE id=?", (inp.product_id,)).fetchone()
    if not row:
        raise HTTPException(400, "Producto inválido")
    total = row["price"] * inp.qty  
    cur.execute(
        "INSERT INTO orders(user_id,product_id,qty,total) VALUES(?,?,?,?)",
        (user["id"], inp.product_id, inp.qty, total)
    )
    con.commit()
    return {"message": "order_created", "qty": inp.qty, "total": total}


@app.get("/admin/users")
def admin_users(request: Request, as_role: str | None = None):
    
    if as_role == "admin":
        fake = {"id": -1, "email": "spoof@attacker", "role": "admin"}
        resp = Response()
        set_session_cookie(resp, **fake)  
       
        resp.media_type = "application/json"
        resp.body = json.dumps({"message": "spoofed admin"}).encode()
        return resp

    user = get_session_user(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "Solo admin")
    con = db(); cur = con.cursor()
    rows = cur.execute("SELECT id,email,password,role FROM users").fetchall()  
    return {"users": [dict(r) for r in rows]}


@app.get("/forgot")
def forgot(email: str):
    token = "reset-" + email.replace("@", "-")
    return {"reset_token": token, "note": "token predecible (demo)"}


@app.get("/config")
def config_dump():
    
    return {
        "env": dict(os.environ),
        "debug": True,
        "note": "Exposición de configuración (demo insegura)"
    }


@app.get("/fetch")
def fetch(url: str = "http://127.0.0.1:8000/health"):
    try:
        r = requests.get(url, timeout=5) 
        return {"url": url, "status_code": r.status_code, "body": r.text[:2000]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/import-catalog")
def import_catalog(url: str):
    data = requests.get(url, timeout=5).json()  
    con = db(); cur = con.cursor()
    inserted = 0
    for item in data:
        cur.execute("INSERT INTO products(name,price) VALUES(?,?)",
                    (item.get("name", "item"), float(item.get("price", 1.0))))
        inserted += 1
    con.commit()
    return {"imported": inserted, "from": url}

@app.post("/parse-yaml")
async def parse_yaml(request: Request):
    body = await request.body()
   
    try:
        parsed = yaml.load(body.decode(), Loader=None)  
        return {"parsed": parsed}
    except Exception as e:
        return {"error": str(e)}


@app.get("/component-version")
def component_version():
    return {
        "component": "yaml (PyYAML)",
        "usage": "yaml.load sin SafeLoader",
        "risk": "Si se usa versión antigua de PyYAML, aumenta superficie de RCE",
    }


@app.get("/health")
def health():
    return {"status": "ok"}  

@app.middleware("http")
async def swallow_errors(request: Request, call_next):

    try:
        resp = await call_next(request)
        return resp
    except Exception as e:
        return Response(content=json.dumps({"error_swallowed": str(e)}), media_type="application/json")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
