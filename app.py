"""Saarthi — AI-assisted victim well-being monitoring (SIH prototype).

This demo provides decision support only. Scores are not a medical diagnosis and
every alert requires review by an authorised human professional.
"""
from __future__ import annotations

import json
import re
import sqlite3
import base64
import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "saarthi.db"

app = FastAPI(title="Saarthi Well-being Monitor", version="1.0.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def iso_after(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()


def rows(items):
    return [dict(item) for item in items]


# Defined early because role-protected API routes are registered below. The same
# verification policy is used by the explicit sign-in endpoints later in file.
AUTH_SECRET = os.environ.get("SAARTHI_AUTH_SECRET", "development-only-change-this-secret")
AUTH_COOKIE = "saarthi_session"


def token_user(token: str | None):
    if not token or "." not in token: return None
    payload, signature = token.rsplit(".", 1)
    expected = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected): return None
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        user_id, role, expiry = raw.split(":")
        return (int(user_id), role) if int(expiry) >= int(datetime.now(timezone.utc).timestamp()) else None
    except (ValueError, UnicodeDecodeError): return None


def current_user(saarthi_session: str | None = Cookie(default=None)):
    identity = token_user(saarthi_session)
    if not identity: raise HTTPException(401, "Please sign in to continue.")
    with db() as con: user = con.execute("SELECT id,email,role,display_name,case_id,active FROM users WHERE id=?", (identity[0],)).fetchone()
    if not user or not user["active"]: raise HTTPException(401, "Your session is no longer active.")
    return dict(user)


def role_required(*roles):
    def enforce(user=Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(403, "This account role cannot access this workspace.")
        return user
    return enforce


def init_db() -> None:
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
              case_id TEXT PRIMARY KEY, alias TEXT NOT NULL, district TEXT NOT NULL,
              stage TEXT NOT NULL, language TEXT NOT NULL, channel TEXT NOT NULL,
              frequency INTEGER NOT NULL, phone_masked TEXT NOT NULL, consent INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'Monitoring', next_checkin TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkins (
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, created_at TEXT NOT NULL,
              channel TEXT NOT NULL, message TEXT NOT NULL, self_rating INTEGER NOT NULL,
              score INTEGER NOT NULL, risk TEXT NOT NULL, signals TEXT NOT NULL, explanation TEXT NOT NULL,
              support_requested INTEGER NOT NULL DEFAULT 0,
              FOREIGN KEY(case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, created_at TEXT NOT NULL,
              severity TEXT NOT NULL, title TEXT NOT NULL, reasons TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'Open', acknowledged_at TEXT
            );
            CREATE TABLE IF NOT EXISTS interventions (
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, created_at TEXT NOT NULL,
              kind TEXT NOT NULL, notes TEXT NOT NULL, owner TEXT NOT NULL, followup_date TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'Completed'
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor TEXT NOT NULL,
              action TEXT NOT NULL, case_id TEXT, detail TEXT NOT NULL
            );
            """
        )
        if con.execute("SELECT count(*) FROM cases").fetchone()[0]:
            return
        created = now()
        seed_cases = [
            ("NHAA-1024", "Case A-1024", "Bhopal", "Investigation", "Hindi", "IVRS", 7, "+91 •••• 1842", 1, "Priority review", iso_after(2), created),
            ("NHAA-1088", "Case B-1088", "Indore", "Trial", "English", "Chatbot", 7, "+91 •••• 7721", 1, "Monitoring", iso_after(4), created),
            ("NHAA-1091", "Case C-1091", "Gwalior", "Investigation", "Hindi", "SMS", 14, "+91 •••• 4095", 1, "Monitoring", iso_after(9), created),
            ("NHAA-1112", "Case D-1112", "Jabalpur", "Rehabilitation", "English", "Chatbot", 14, "+91 •••• 9358", 1, "Monitoring", iso_after(12), created),
        ]
        con.executemany("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", seed_cases)
        history = [
            ("NHAA-1024", -28, "IVRS", "I am managing, but the hearing makes me anxious.", 2),
            ("NHAA-1024", -20, "IVRS", "I feel worried about the court process.", 3),
            ("NHAA-1024", -12, "IVRS", "They threatened me again yesterday. I am scared.", 4),
            ("NHAA-1088", -21, "Chatbot", "The process is slow and I feel stressed sometimes.", 2),
            ("NHAA-1088", -14, "Chatbot", "I am worried about the next hearing.", 3),
            ("NHAA-1088", -7, "Chatbot", "I need some support but feel safe today.", 3),
            ("NHAA-1091", -14, "SMS", "1", 1),
            ("NHAA-1091", -2, "SMS", "2", 2),
            ("NHAA-1112", -18, "Chatbot", "Counselling has been helpful. I feel better.", 2),
            ("NHAA-1112", -4, "Chatbot", "I am doing okay and have support.", 1),
        ]
        for case_id, ago, channel, message, rating in history:
            created_at = (datetime.now(timezone.utc) + timedelta(days=ago)).replace(microsecond=0).isoformat()
            result = analyse(message, rating, case_id, con)
            con.execute(
                "INSERT INTO checkins(case_id,created_at,channel,message,self_rating,score,risk,signals,explanation,support_requested) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (case_id, created_at, channel, message, rating, result["score"], result["risk"], json.dumps(result["signals"]), json.dumps(result["explanation"]), int(result["support_requested"])),
            )
        con.execute("INSERT INTO alerts(case_id,created_at,severity,title,reasons,status) VALUES (?,?,?,?,?,?)", (
            "NHAA-1024", now(), "Priority", "Rapidly increasing distress", json.dumps(["Threat/intimidation language detected", "Score increased in consecutive check-ins", "High self-reported distress"]), "Open"))
        con.execute("INSERT INTO interventions(case_id,created_at,kind,notes,owner,followup_date,status) VALUES (?,?,?,?,?,?,?)", (
            "NHAA-1112", now(), "Counselling follow-up", "Victim reported improved wellbeing after referral.", "Counsellor Meera", iso_after(10), "Completed"))


def analyse(message: str, rating: int, case_id: str, con: sqlite3.Connection) -> dict:
    text = (message or "").lower()
    groups = {
        "Threat / intimidation": ["threat", "threatened", "intimidat", "pressure", "followed", "danger"],
        "Fear / anxiety": ["scared", "fear", "afraid", "worried", "anxious", "panic"],
        "Process-related stress": ["court", "hearing", "investigation", "delay", "case", "process"],
        "Support need": ["help", "support", "call", "counsell", "contact"],
        "Low mood": ["hopeless", "alone", "isolated", "cannot cope", "no one", "sleep"],
        "Immediate safety language": ["hurt myself", "end my life", "kill", "immediate danger", "attack"],
    }
    signals = [label for label, words in groups.items() if any(word in text for word in words)]
    score = {1: 14, 2: 32, 3: 56, 4: 76}.get(rating, 35)
    weights = {"Threat / intimidation": 17, "Fear / anxiety": 8, "Process-related stress": 5, "Support need": 6, "Low mood": 12, "Immediate safety language": 24}
    score += sum(weights[s] for s in signals)
    prior = [r[0] for r in con.execute("SELECT score FROM checkins WHERE case_id=? ORDER BY created_at DESC LIMIT 2", (case_id,))]
    trend = 0
    if prior:
        trend = score - prior[0]
        if trend >= 12:
            score += 6
    missed = con.execute("SELECT count(*) FROM checkins WHERE case_id=? AND channel='Missed'", (case_id,)).fetchone()[0]
    if missed:
        score += min(missed * 3, 9)
        signals.append("Missed engagement")
    score = max(0, min(100, round(score)))
    risk = "Routine" if score <= 30 else "Watch" if score <= 50 else "Review" if score <= 70 else "Priority" if score <= 85 else "Critical"
    explanation = [f"Self-reported response indicates {'low' if rating == 1 else 'moderate' if rating == 2 else 'high' if rating == 3 else 'very high'} distress."]
    if signals:
        explanation.append("Detected: " + ", ".join(signals) + ".")
    if trend >= 12:
        explanation.append(f"Score increased {trend} points since the prior check-in.")
    if not signals and rating <= 2:
        explanation.append("No acute concern language was detected in this check-in.")
    return {"score": score, "risk": risk, "signals": signals, "explanation": explanation, "support_requested": "Support need" in signals or rating == 4}


class CaseCreate(BaseModel):
    case_id: str = Field(pattern=r"^[A-Za-z0-9-]{4,32}$")
    alias: str = Field(min_length=3, max_length=60)
    district: str = Field(min_length=2, max_length=60)
    stage: str
    language: Literal["English", "Hindi"]
    channel: Literal["Chatbot", "IVRS", "SMS"]
    frequency: int = Field(ge=3, le=30)
    phone_masked: str = Field(min_length=6, max_length=30)
    consent: bool


class CheckinCreate(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    self_rating: int = Field(ge=1, le=4)
    channel: Literal["Chatbot", "IVRS", "SMS"] = "Chatbot"


class InterventionCreate(BaseModel):
    kind: str = Field(min_length=3, max_length=80)
    notes: str = Field(min_length=3, max_length=1000)
    owner: str = Field(min_length=2, max_length=80)
    followup_days: int = Field(ge=1, le=60)


@app.on_event("startup")
def startup():
    init_db()
    init_identity()


@app.get("/")
def home():
    return RedirectResponse("/signin", status_code=302)


@app.get("/api/dashboard")
def dashboard(user=Depends(role_required("officer", "counsellor", "admin"))):
    with db() as con:
        total = con.execute("SELECT count(*) FROM cases").fetchone()[0]
        latest = con.execute("""SELECT c.case_id,c.alias,c.district,c.stage,c.channel,c.language,c.status,c.next_checkin,
            ci.score,ci.risk,ci.created_at FROM cases c LEFT JOIN checkins ci ON ci.id=(SELECT id FROM checkins WHERE case_id=c.case_id ORDER BY created_at DESC LIMIT 1)
            ORDER BY COALESCE(ci.score,0) DESC""").fetchall()
        open_alerts = con.execute("SELECT count(*) FROM alerts WHERE status='Open'").fetchone()[0]
        pending = con.execute("SELECT count(*) FROM interventions WHERE status='Pending'").fetchone()[0]
        high = sum(1 for x in latest if (x["score"] or 0) >= 71)
        rising = 0
        for item in latest:
            scores = [r[0] for r in con.execute("SELECT score FROM checkins WHERE case_id=? ORDER BY created_at DESC LIMIT 2", (item["case_id"],))]
            if len(scores) == 2 and scores[0] - scores[1] >= 10:
                rising += 1
        return {"metrics": {"active_cases": total, "high_priority": high, "requiring_review": open_alerts, "rising_distress": rising, "pending_intervention": pending}, "cases": rows(latest)}


@app.get("/api/cases")
def list_cases(user=Depends(role_required("officer", "counsellor", "admin"))):
    return dashboard(user)["cases"]


@app.get("/api/cases/{case_id}")
def case_detail(case_id: str, user=Depends(role_required("officer", "counsellor", "admin"))):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        checkins = rows(con.execute("SELECT * FROM checkins WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall())
        for checkin in checkins:
            checkin["signals"] = json.loads(checkin["signals"])
            checkin["explanation"] = json.loads(checkin["explanation"])
        alerts = rows(con.execute("SELECT * FROM alerts WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall())
        for alert in alerts: alert["reasons"] = json.loads(alert["reasons"])
        interventions = rows(con.execute("SELECT * FROM interventions WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall())
        return {"case": dict(case), "checkins": checkins, "alerts": alerts, "interventions": interventions}


@app.post("/api/cases", status_code=201)
def create_case(payload: CaseCreate, user=Depends(role_required("officer", "admin"))):
    if not payload.consent:
        raise HTTPException(400, "Consent/notice acknowledgement is required before monitoring.")
    with db() as con:
        if con.execute("SELECT 1 FROM cases WHERE case_id=?", (payload.case_id,)).fetchone():
            raise HTTPException(409, "This Case ID already exists.")
        con.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (payload.case_id.upper(), payload.alias, payload.district, payload.stage, payload.language, payload.channel, payload.frequency, payload.phone_masked, 1, "Monitoring", iso_after(payload.frequency), now()))
        con.execute("INSERT INTO audit_log(created_at,actor,action,case_id,detail) VALUES (?,?,?,?,?)", (now(), "Officer demo", "Created monitoring case", payload.case_id.upper(), "Consent acknowledged"))
    return {"ok": True, "case_id": payload.case_id.upper()}


@app.post("/api/cases/{case_id}/checkins")
def create_checkin(case_id: str, payload: CheckinCreate, user=Depends(role_required("officer", "counsellor", "admin"))):
    with db() as con:
        case = con.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not case: raise HTTPException(404, "Case not found")
        result = analyse(payload.message, payload.self_rating, case_id, con)
        con.execute("INSERT INTO checkins(case_id,created_at,channel,message,self_rating,score,risk,signals,explanation,support_requested) VALUES (?,?,?,?,?,?,?,?,?,?)", (case_id, now(), payload.channel, payload.message, payload.self_rating, result["score"], result["risk"], json.dumps(result["signals"]), json.dumps(result["explanation"]), int(result["support_requested"])))
        con.execute("UPDATE cases SET next_checkin=?,status=? WHERE case_id=?", (iso_after(case["frequency"]), "Priority review" if result["risk"] in ("Priority", "Critical") else "Monitoring", case_id))
        if result["risk"] in ("Priority", "Critical") or (result["risk"] == "Review" and result["support_requested"]):
            title = "Critical human assessment required" if result["risk"] == "Critical" else "Human review recommended"
            reasons = result["explanation"]
            con.execute("INSERT INTO alerts(case_id,created_at,severity,title,reasons,status) VALUES (?,?,?,?,?,?)", (case_id, now(), result["risk"], title, json.dumps(reasons), "Open"))
        con.execute("INSERT INTO audit_log(created_at,actor,action,case_id,detail) VALUES (?,?,?,?,?)", (now(), "Monitoring engine", "Analysed check-in", case_id, f"Score {result['score']}"))
    return {"ok": True, **result}


@app.post("/api/cases/{case_id}/simulate-ivrs")
def simulate_ivrs(case_id: str, payload: CheckinCreate, user=Depends(role_required("officer", "counsellor", "admin"))):
    payload.channel = "IVRS"
    return create_checkin(case_id, payload, user)


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, user=Depends(role_required("officer", "counsellor", "admin"))):
    with db() as con:
        alert = con.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not alert: raise HTTPException(404, "Alert not found")
        con.execute("UPDATE alerts SET status='Acknowledged',acknowledged_at=? WHERE id=?", (now(), alert_id))
        con.execute("INSERT INTO audit_log(created_at,actor,action,case_id,detail) VALUES (?,?,?,?,?)", (now(), "Officer demo", "Acknowledged alert", alert["case_id"], f"Alert #{alert_id}"))
    return {"ok": True}


@app.post("/api/cases/{case_id}/interventions", status_code=201)
def create_intervention(case_id: str, payload: InterventionCreate, user=Depends(role_required("officer", "counsellor", "admin"))):
    with db() as con:
        if not con.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone(): raise HTTPException(404, "Case not found")
        followup = iso_after(payload.followup_days)
        con.execute("INSERT INTO interventions(case_id,created_at,kind,notes,owner,followup_date,status) VALUES (?,?,?,?,?,?,?)", (case_id, now(), payload.kind, payload.notes, payload.owner, followup, "Completed"))
        con.execute("UPDATE cases SET next_checkin=?,status='Monitoring' WHERE case_id=?", (followup, case_id))
        con.execute("INSERT INTO audit_log(created_at,actor,action,case_id,detail) VALUES (?,?,?,?,?)", (now(), payload.owner, "Recorded intervention", case_id, payload.kind))
    return {"ok": True, "followup_date": followup}


@app.get("/api/safety")
def safety():
    return {"notice": "This prototype is an early-warning decision-support tool, not a diagnostic or emergency service. Any elevated result must be reviewed by an authorised human professional.", "privacy": ["Role-based access design", "Pseudonymous case display", "Audit logging", "Consent acknowledgement", "No model training on conversation data"]}


@app.get("/health")
def health():
    return {"status": "ok", "service": "Saarthi"}


# --- Identity, role boundaries and victim self-service ---------------------------------
# In production, replace the demo account provisioning below with an approved identity
# verification/invitation process and store the signing key in a managed secret store.
AUTH_SECRET = os.environ.get("SAARTHI_AUTH_SECRET", "development-only-change-this-secret")
AUTH_COOKIE = "saarthi_session"


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
    return f"pbkdf2_sha256${salt}${base64.b64encode(digest).decode()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        _, salt, expected = stored.split("$", 2)
        return hmac.compare_digest(password_hash(password, salt), stored)
    except ValueError:
        return False


def token_for(user_id: int, role: str) -> str:
    exp = int((datetime.now(timezone.utc) + timedelta(hours=8)).timestamp())
    payload = base64.urlsafe_b64encode(f"{user_id}:{role}:{exp}".encode()).decode().rstrip("=")
    signature = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def token_user(token: str | None):
    if not token or "." not in token:
        return None
    payload, signature = token.rsplit(".", 1)
    expected = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        user_id, role, expiry = raw.split(":")
        if int(expiry) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return int(user_id), role
    except (ValueError, UnicodeDecodeError):
        return None


def current_user(saarthi_session: str | None = Cookie(default=None)):
    identity = token_user(saarthi_session)
    if not identity:
        raise HTTPException(401, "Please sign in to continue.")
    with db() as con:
        user = con.execute("SELECT id,email,role,display_name,case_id,active FROM users WHERE id=?", (identity[0],)).fetchone()
    if not user or not user["active"]:
        raise HTTPException(401, "Your session is no longer active.")
    return dict(user)


def role_required(*roles):
    def enforce(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "This account role cannot access this workspace.")
        return user
    return enforce


def init_identity() -> None:
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('victim','officer','counsellor','admin')),
          display_name TEXT NOT NULL, case_id TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS victim_profiles (
          user_id INTEGER PRIMARY KEY, phone TEXT, preferred_language TEXT NOT NULL DEFAULT 'English',
          preferred_channel TEXT NOT NULL DEFAULT 'SMS', sms_opt_in INTEGER NOT NULL DEFAULT 1,
          call_opt_in INTEGER NOT NULL DEFAULT 0, quiet_hours TEXT NOT NULL DEFAULT '21:00–08:00', updated_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS reminders (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, scheduled_at TEXT NOT NULL,
          channel TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Scheduled', created_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        demo = [
            ("officer@saarthi.demo", "Officer@123", "officer", "Aarav Mehta", None),
            ("counsellor@saarthi.demo", "Counsellor@123", "counsellor", "Meera Sharma", None),
            ("victim@saarthi.demo", "Victim@123", "victim", "Case A participant", "NHAA-1024"),
        ]
        for email, password, role, name, case_id in demo:
            if not con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                con.execute("INSERT INTO users(email,password_hash,role,display_name,case_id,created_at) VALUES (?,?,?,?,?,?)", (email, password_hash(password), role, name, case_id, now()))
        victim = con.execute("SELECT id FROM users WHERE email='victim@saarthi.demo'").fetchone()
        if victim and not con.execute("SELECT 1 FROM victim_profiles WHERE user_id=?", (victim[0],)).fetchone():
            con.execute("INSERT INTO victim_profiles(user_id,phone,preferred_language,preferred_channel,sms_opt_in,call_opt_in,quiet_hours,updated_at) VALUES (?,?,?,?,?,?,?,?)", (victim[0], "+91 •••• 1842", "Hindi", "IVRS", 1, 1, "21:00–08:00", now()))
            con.execute("INSERT INTO reminders(user_id,scheduled_at,channel,message,status,created_at) VALUES (?,?,?,?,?,?)", (victim[0], iso_after(2), "SMS", "Saarthi check-in reminder: reply privately when it is safe for you.", "Scheduled", now()))


class SignUp(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=10, max_length=128)
    display_name: str = Field(min_length=2, max_length=80)
    role: Literal["victim", "officer", "counsellor"]
    case_id: str | None = Field(default=None, max_length=32)


class SignIn(BaseModel):
    email: str
    password: str


class ContactPreferences(BaseModel):
    phone: str = Field(min_length=8, max_length=25)
    preferred_language: Literal["English", "Hindi"]
    preferred_channel: Literal["SMS", "IVRS", "Chatbot"]
    sms_opt_in: bool = True
    call_opt_in: bool = False
    quiet_hours: str = Field(min_length=5, max_length=30)


class VictimChat(BaseModel):
    message: str = Field(min_length=1, max_length=1600)
    self_rating: int = Field(ge=1, le=4)


@app.get("/signin")
def signin_page(): return FileResponse(ROOT / "static" / "signin.html")


@app.get("/signup")
def signup_page(): return FileResponse(ROOT / "static" / "signup.html")


@app.get("/victim")
def victim_page(): return FileResponse(ROOT / "static" / "victim.html")


@app.get("/officer")
def officer_page(): return FileResponse(ROOT / "static" / "index.html")


@app.post("/api/auth/signup", status_code=201)
def signup(payload: SignUp):
    email = payload.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Enter a valid email address.")
    if not re.search(r"[A-Z]", payload.password) or not re.search(r"[a-z]", payload.password) or not re.search(r"\d", payload.password):
        raise HTTPException(400, "Password must include upper-case, lower-case, and a number.")
    if payload.role == "victim" and not payload.case_id:
        raise HTTPException(400, "A Case ID is required for the victim workspace.")
    with db() as con:
        if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone(): raise HTTPException(409, "An account with this email already exists.")
        if payload.case_id and not con.execute("SELECT 1 FROM cases WHERE case_id=?", (payload.case_id.upper(),)).fetchone(): raise HTTPException(404, "The Case ID could not be verified in this demo.")
        con.execute("INSERT INTO users(email,password_hash,role,display_name,case_id,created_at) VALUES (?,?,?,?,?,?)", (email, password_hash(payload.password), payload.role, payload.display_name, payload.case_id.upper() if payload.case_id else None, now()))
        user_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        if payload.role == "victim": con.execute("INSERT INTO victim_profiles(user_id,updated_at) VALUES (?,?)", (user_id, now()))
    return {"ok": True, "message": "Account created. Sign in to continue."}


@app.post("/api/auth/signin")
def signin(payload: SignIn, response: Response):
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE email=?", (payload.email.strip().lower(),)).fetchone()
    if not user or not user["active"] or not password_matches(payload.password, user["password_hash"]): raise HTTPException(401, "Invalid email or password.")
    response.set_cookie(AUTH_COOKIE, token_for(user["id"], user["role"]), httponly=True, secure=False, samesite="lax", max_age=28_800)
    return {"ok": True, "role": user["role"], "redirect": "/victim" if user["role"] == "victim" else "/officer"}


@app.post("/api/auth/signout")
def signout(response: Response):
    response.delete_cookie(AUTH_COOKIE); return {"ok": True}


@app.get("/api/auth/me")
def me(user=Depends(current_user)): return user


@app.get("/api/victim/dashboard")
def victim_dashboard(user=Depends(role_required("victim"))):
    with db() as con:
        profile = con.execute("SELECT * FROM victim_profiles WHERE user_id=?", (user["id"],)).fetchone()
        case = con.execute("SELECT * FROM cases WHERE case_id=?", (user["case_id"],)).fetchone()
        checkins = rows(con.execute("SELECT created_at,score,risk,channel,message FROM checkins WHERE case_id=? ORDER BY created_at DESC LIMIT 6", (user["case_id"],)).fetchall())
        reminders = rows(con.execute("SELECT * FROM reminders WHERE user_id=? ORDER BY scheduled_at DESC LIMIT 10", (user["id"],)).fetchall())
    return {"user": user, "profile": dict(profile) if profile else {}, "case": dict(case) if case else {}, "checkins": checkins, "reminders": reminders, "safety_note": "If you are in immediate danger, use local emergency support or contact a trusted person. Saarthi check-ins are not an emergency service."}


@app.put("/api/victim/contact")
def update_contact(payload: ContactPreferences, user=Depends(role_required("victim"))):
    with db() as con:
        con.execute("UPDATE victim_profiles SET phone=?,preferred_language=?,preferred_channel=?,sms_opt_in=?,call_opt_in=?,quiet_hours=?,updated_at=? WHERE user_id=?", (payload.phone, payload.preferred_language, payload.preferred_channel, int(payload.sms_opt_in), int(payload.call_opt_in), payload.quiet_hours, now(), user["id"]))
        con.execute("INSERT INTO audit_log(created_at,actor,action,case_id,detail) VALUES (?,?,?,?,?)", (now(), user["display_name"], "Updated contact preferences", user["case_id"], "Victim self-service"))
    return {"ok": True}


@app.post("/api/victim/chat")
def victim_chat(payload: VictimChat, user=Depends(role_required("victim"))):
    # Persist the response through the same explainable monitoring engine used by IVRS/SMS.
    with db() as con:
        result = analyse(payload.message, payload.self_rating, user["case_id"], con)
        con.execute("INSERT INTO checkins(case_id,created_at,channel,message,self_rating,score,risk,signals,explanation,support_requested) VALUES (?,?,?,?,?,?,?,?,?,?)", (user["case_id"], now(), "Chatbot", payload.message, payload.self_rating, result["score"], result["risk"], json.dumps(result["signals"]), json.dumps(result["explanation"]), int(result["support_requested"])))
        if result["risk"] in ("Priority", "Critical"):
            con.execute("INSERT INTO alerts(case_id,created_at,severity,title,reasons,status) VALUES (?,?,?,?,?,?)", (user["case_id"], now(), result["risk"], "Human review recommended from victim check-in", json.dumps(result["explanation"]), "Open"))
        reply = "Thank you for sharing that. Your response has been recorded for the support team."
        if result["risk"] in ("Priority", "Critical"): reply = "Thank you for telling us. An authorised support professional will review this check-in. If you feel unsafe right now, please use immediate local emergency support or contact someone you trust."
        elif result["support_requested"]: reply = "Thank you for asking for support. Your request has been noted for authorised follow-up."
    return {"ok": True, "reply": reply, "risk": result["risk"], "score": result["score"]}
