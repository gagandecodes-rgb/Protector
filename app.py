import os
import re
import time
import sqlite3
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

# ---------------- CONFIG ----------------
DB_PATH = os.getenv("DB_PATH", "validator.db")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-me")  # set in Render env
MAX_CODES_PER_REQUEST = int(os.getenv("MAX_CODES_PER_REQUEST", "500"))

CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{4,64}$")

app = FastAPI(title="Coupon Validator API", version="1.0.0")


# ---------------- DB ----------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS coupons (
        code TEXT PRIMARY KEY,
        working INTEGER NOT NULL DEFAULT 1,        -- 1=active, 0=disabled
        expires_at INTEGER DEFAULT NULL,           -- unix seconds
        max_uses INTEGER DEFAULT NULL,             -- NULL=unlimited
        used_count INTEGER NOT NULL DEFAULT 0,
        note TEXT DEFAULT ''
    )
    """)
    conn.commit()
    conn.close()

@app.on_event("startup")
def _startup():
    init_db()


# ---------------- MODELS ----------------
class ValidateRequest(BaseModel):
    # Optional client token (you can pass whatever you want; can be ignored or enforced)
    token: Optional[str] = None
    coupons: List[str] = Field(default_factory=list)

class ValidateResult(BaseModel):
    code: str
    working: bool
    reason: str = ""

class ValidateResponse(BaseModel):
    results: List[ValidateResult]

class UpsertCoupon(BaseModel):
    code: str
    working: bool = True
    expires_at: Optional[int] = None  # unix seconds
    max_uses: Optional[int] = None
    note: str = ""

class UpsertResponse(BaseModel):
    ok: bool
    inserted_or_updated: int

class CouponRow(BaseModel):
    code: str
    working: bool
    expires_at: Optional[int]
    max_uses: Optional[int]
    used_count: int
    note: str


# ---------------- HELPERS ----------------
def normalize_code(s: str) -> str:
    s = (s or "").strip()
    return s.upper()

def validate_format(code: str) -> Optional[str]:
    if not code:
        return "empty"
    if not CODE_RE.match(code):
        return "bad_format"
    return None

def fetch_coupon(code: str) -> Optional[Dict[str, Any]]:
    conn = db()
    cur = conn.execute(
        "SELECT code, working, expires_at, max_uses, used_count, note FROM coupons WHERE code=?",
        (code,)
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "code": row[0],
        "working": bool(row[1]),
        "expires_at": row[2],
        "max_uses": row[3],
        "used_count": row[4],
        "note": row[5] or ""
    }

def is_coupon_working(row: Dict[str, Any]) -> (bool, str):
    now = int(time.time())

    if not row["working"]:
        return False, "disabled"

    exp = row["expires_at"]
    if exp is not None and now >= int(exp):
        return False, "expired"

    max_uses = row["max_uses"]
    if max_uses is not None and int(row["used_count"]) >= int(max_uses):
        return False, "max_uses_reached"

    return True, "ok"


# ---------------- ROUTES ----------------
@app.get("/")
def root():
    return {"ok": True, "service": "coupon-validator", "time": int(time.time())}

@app.post("/validate", response_model=ValidateResponse)
def validate(req: ValidateRequest):
    coupons = [normalize_code(c) for c in (req.coupons or [])]
    coupons = [c for c in coupons if c]  # remove empties

    if len(coupons) == 0:
        return {"results": []}

    if len(coupons) > MAX_CODES_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Too many coupons (max {MAX_CODES_PER_REQUEST})")

    results: List[ValidateResult] = []

    for code in coupons:
        fmt = validate_format(code)
        if fmt:
            results.append(ValidateResult(code=code, working=False, reason=fmt))
            continue

        row = fetch_coupon(code)
        if not row:
            results.append(ValidateResult(code=code, working=False, reason="not_found"))
            continue

        ok, reason = is_coupon_working(row)
        results.append(ValidateResult(code=code, working=ok, reason=reason))

    return {"results": results}

# ---- Admin: Add/Update coupons ----
@app.post("/admin/upsert", response_model=UpsertResponse)
def admin_upsert(items: List[UpsertCoupon], x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not items:
        return {"ok": True, "inserted_or_updated": 0}

    conn = db()
    count = 0
    for it in items:
        code = normalize_code(it.code)
        fmt = validate_format(code)
        if fmt:
            continue
        conn.execute(
            "INSERT INTO coupons(code, working, expires_at, max_uses, used_count, note) "
            "VALUES(?,?,?,?,COALESCE((SELECT used_count FROM coupons WHERE code=?),0),?) "
            "ON CONFLICT(code) DO UPDATE SET working=excluded.working, expires_at=excluded.expires_at, "
            "max_uses=excluded.max_uses, note=excluded.note",
            (
                code,
                1 if it.working else 0,
                it.expires_at,
                it.max_uses,
                code,
                it.note or ""
            )
        )
        count += 1

    conn.commit()
    conn.close()
    return {"ok": True, "inserted_or_updated": count}

@app.get("/admin/list", response_model=List[CouponRow])
def admin_list(limit: int = 200, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    limit = max(1, min(1000, limit))
    conn = db()
    cur = conn.execute(
        "SELECT code, working, expires_at, max_uses, used_count, note FROM coupons ORDER BY code LIMIT ?",
        (limit,)
    )
    rows = cur.fetchall()
    conn.close()

    out = []
    for r in rows:
        out.append(CouponRow(
            code=r[0],
            working=bool(r[1]),
            expires_at=r[2],
            max_uses=r[3],
            used_count=r[4],
            note=r[5] or ""
        ))
    return out
