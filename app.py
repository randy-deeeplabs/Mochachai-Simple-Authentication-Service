import os
from typing import Optional
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, String, Integer, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from passlib.hash import bcrypt

DB_URL = os.getenv("DB_URL", "sqlite:///./auth.db")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "change-me-now")

app = FastAPI(title="SimpleAuth")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))

Base.metadata.create_all(engine)

def get_db():
    with Session(engine) as s:
        yield s

def require_admin(creds: HTTPBasicCredentials = Depends(security)):
    if not (creds.username == ADMIN_USER and creds.password == ADMIN_PASS):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

def hash_pw(pw: str) -> str:
    return bcrypt.hash(pw)

def verify_pw(pw: str, pw_hash: str) -> bool:
    return bcrypt.verify(pw, pw_hash)

@app.get("/admin/users", response_class=HTMLResponse)
def admin_list(request: Request, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User)).all()
    return templates.TemplateResponse("admin_list.html", {"request": request, "users": users})

@app.get("/admin/users/new", response_class=HTMLResponse)
def admin_new(request: Request, _: bool = Depends(require_admin)):
    return templates.TemplateResponse("admin_form.html", {"request": request, "user": None})

@app.post("/admin/users/new")
def admin_create(_: bool = Depends(require_admin),
                 name: str = Form(...), email: str = Form(...), password: str = Form(...),
                 db: Session = Depends(get_db)):
    email = email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        return PlainTextResponse("Email already exists", status_code=400)
    db.add(User(name=name.strip(), email=email, password_hash=hash_pw(password)))
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def admin_edit(user_id: int, request: Request, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(404)
    return templates.TemplateResponse("admin_form.html", {"request": request, "user": u})

@app.post("/admin/users/{user_id}/update")
def admin_update(user_id: int, _: bool = Depends(require_admin),
                 name: str = Form(...), email: str = Form(...), password: Optional[str] = Form(None),
                 db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(404)
    email = email.strip().lower()
    if email != u.email and db.scalar(select(User).where(User.email == email)):
        return PlainTextResponse("Email already exists", status_code=400)
    u.name, u.email = name.strip(), email
    if password: u.password_hash = hash_pw(password)
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/admin/users/{user_id}/delete")
def admin_delete(user_id: int, _: bool = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(404)
    db.delete(u); db.commit()
    return RedirectResponse(url="/admin/users", status_code=303)

@app.post("/api/login")
async def api_login(payload: dict, db: Session = Depends(get_db)):
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    if not email or not password:
        return JSONResponse({"status": "fail"}, status_code=400)
    u = db.scalar(select(User).where(User.email == email))
    if u and verify_pw(password, u.password_hash):
        return JSONResponse({"status": "success"}, status_code=200)
    return JSONResponse({"status": "fail"}, status_code=401)

@app.get("/healthz")
def healthz():
    return {"ok": True}
