"""Zimbra Mailbox Lifecycle Management Engine - FastAPI Application."""
from __future__ import annotations

import io
import csv
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db, SessionLocal
from app.zimbra_client import zimbra_client
from app.config import settings
from app.models import Account, User, SyncLog, Domain
from app.auth import (
    get_current_user, require_admin,
    hash_password, verify_password, create_token, seed_users,
)
from app import services, cache

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Zimbra Lifecycle Manager starting up")
    logger.info("Redis available: %s", cache.ping())
    db = SessionLocal()
    try:
        seed_users(db)
    finally:
        db.close()
    yield
    await zimbra_client.close()
    logger.info("Zimbra Lifecycle Manager shut down")


app = FastAPI(
    title="Zimbra Mailbox Lifecycle Manager",
    version="1.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Pydantic schemas ─────────────────────────────────────────────────

def _validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")


class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str = ""
    role: str = "operator"

class UserUpdate(BaseModel):
    display_name: str = None
    role: str = None
    is_active: bool = None

class PasswordChange(BaseModel):
    password: str


# ── UI ────────────────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse("static/index.html")

@app.get("/login")
async def login_page():
    return FileResponse("static/login.html")


# ── Auth ──────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.headers.get("X-Real-IP", request.client.host)
    rate_key = f"login:{client_ip}"
    if cache.check_rate_limit(rate_key, max_attempts=5, window=300):
        raise HTTPException(429, "Too many login attempts — try again in 5 minutes")

    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")

    cache.clear_rate_limit(rate_key)
    token = create_token(user.id, user.username, user.role, user.token_version)
    return {
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
        },
    }

@app.get("/api/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
    }


# ── User Management (admin only) ─────────────────────────────────────

@app.get("/api/users")
def list_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(User).order_by(User.username).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": str(u.created_at) if u.created_at else None,
        }
        for u in users
    ]

@app.post("/api/users")
def create_user(
    body: UserCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(400, "Username already exists")
    if body.role not in ("admin", "operator"):
        raise HTTPException(400, "Role must be 'admin' or 'operator'")
    _validate_password(body.password)
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        display_name=body.display_name or body.username,
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}

@app.put("/api/users/{user_id}")
def update_user(
    user_id: int,
    body: UserUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if body.display_name is not None:
        user.display_name = body.display_name
    if body.role is not None:
        if body.role not in ("admin", "operator"):
            raise HTTPException(400, "Role must be 'admin' or 'operator'")
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
        if not body.is_active:
            user.token_version += 1
    db.commit()
    return {"message": "User updated"}

@app.put("/api/users/{user_id}/password")
def change_user_password(
    user_id: int,
    body: PasswordChange,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    _validate_password(body.password)
    user.password_hash = hash_password(body.password)
    user.token_version += 1
    db.commit()
    return {"message": "Password changed"}

@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot delete yourself")
    db.delete(user)
    db.commit()
    return {"message": "User deleted"}


# ── Dashboard ─────────────────────────────────────────────────────────

@app.get("/api/dashboard")
def dashboard_stats(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return services.get_dashboard_stats(db)


# ── Accounts ──────────────────────────────────────────────────────────

@app.get("/api/accounts")
def list_accounts(
    domain: str = Query(None),
    status: str = Query(None),
    search: str = Query(None),
    purge_eligible: bool = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    sort_by: str = Query("email"),
    sort_dir: str = Query("asc"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return services.get_accounts(
        db, domain, status, search, purge_eligible, page, per_page, sort_by, sort_dir
    )


@app.get("/api/accounts/export")
def export_accounts_csv(
    domain: str = Query(None),
    status: str = Query(None),
    search: str = Query(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export filtered accounts as a CSV download."""
    query = db.query(Account)
    if domain:
        query = query.filter(Account.domain == domain)
    if status:
        query = query.filter(Account.account_status == status)
    if search:
        query = query.filter(Account.email.ilike(f"%{search}%"))
    query = query.order_by(Account.email)
    accounts = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "email", "display_name", "domain", "account_status",
        "last_login", "forwarding_addresses", "inactive_since",
    ])
    for a in accounts:
        writer.writerow([
            a.email,
            a.display_name or "",
            a.domain,
            a.account_status,
            str(a.last_login) if a.last_login else "",
            a.forwarding_addresses or "",
            str(a.inactive_since) if a.inactive_since else "",
        ])

    output.seek(0)
    filename = f"accounts_{status or 'all'}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/accounts/{account_id}")
def get_account(
    account_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acct = db.query(Account).filter(Account.id == account_id).first()
    if not acct:
        raise HTTPException(404, "Account not found")
    return services._account_to_dict(acct)


@app.post("/api/accounts/{account_id}/status")
async def change_status(
    account_id: int,
    new_status: str = Query(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        account = await services.change_account_status(
            db, account_id, new_status, admin_user=user.username
        )
        return {
            "message": f"Status changed to {new_status}",
            "account": services._account_to_dict(account),
        }
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/{account_id}/purge")
async def purge_account(
    account_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        result = await services.purge_account(
            db, account_id, admin_user=user.username
        )
        return {"message": f"Account {result['email']} purged", "result": result}
    except ValueError as e:
        raise HTTPException(400, str(e))


# ── CSV Bulk Operations ───────────────────────────────────────────────

@app.post("/api/accounts/bulk-status")
async def bulk_status_from_csv(
    file: UploadFile = File(...),
    new_status: str = Query(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Upload a CSV with an email column. Apply the same new_status to all.
    """
    valid_statuses = {"active", "locked", "closed", "maintenance"}
    if new_status not in valid_statuses:
        raise HTTPException(400, f"Invalid status '{new_status}'. Valid: {', '.join(valid_statuses)}")

    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "File must be a .csv")

    content = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(400, f"File too large (max {settings.MAX_UPLOAD_BYTES // 1024 // 1024} MB)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(400, "CSV is empty or has no headers")

    # Find the email column (case-insensitive)
    headers_lower = [h.strip().lower() for h in reader.fieldnames]
    if "email" not in headers_lower:
        # Try single-column CSV without header
        reader = csv.reader(io.StringIO(text))
        rows = []
        for row in reader:
            if row:
                rows.append(row[0].strip())
        # If first row looks like an email, treat whole file as headerless
        if rows and "@" in rows[0]:
            emails = rows
        else:
            emails = rows[1:]  # skip header row
    else:
        emails = []
        for row in reader:
            row = {k.strip().lower(): v.strip() for k, v in row.items()}
            email = row.get("email", "").strip()
            if email:
                emails.append(email)

    results = {"total": len(emails), "success": 0, "errors": 0, "skipped": 0, "details": []}

    for i, email in enumerate(emails, 1):
        acct = db.query(Account).filter(Account.email == email).first()
        if not acct:
            results["errors"] += 1
            results["details"].append({"row": i, "email": email, "error": "Account not found"})
            continue

        if acct.account_status == new_status:
            results["skipped"] += 1
            results["details"].append({
                "row": i, "email": email, "status": "skipped",
                "message": f"Already {new_status}"
            })
            continue

        try:
            await services.change_account_status(
                db, acct.id, new_status, admin_user=user.username
            )
            results["success"] += 1
            results["details"].append({
                "row": i, "email": email, "status": "success",
                "message": f"{acct.account_status} -> {new_status}"
            })
        except ValueError as e:
            results["errors"] += 1
            results["details"].append({"row": i, "email": email, "error": str(e)})

    cache.invalidate_all()
    return results


@app.post("/api/accounts/bulk-csv")
async def bulk_csv_import(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Upload a CSV to perform bulk status changes.
    CSV format: email,new_status
    Valid statuses: active, locked, closed, maintenance
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "File must be a .csv")

    content = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(400, f"File too large (max {settings.MAX_UPLOAD_BYTES // 1024 // 1024} MB)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))

    # Validate headers
    if not reader.fieldnames:
        raise HTTPException(400, "CSV is empty or has no headers")
    headers_lower = [h.strip().lower() for h in reader.fieldnames]
    if "email" not in headers_lower:
        raise HTTPException(
            400,
            f"CSV must have an 'email' column. Found: {reader.fieldnames}"
        )
    if "new_status" not in headers_lower and "status" not in headers_lower:
        raise HTTPException(
            400,
            "CSV must have a 'new_status' or 'status' column"
        )

    # Determine which column name is used for status
    status_col = "new_status" if "new_status" in headers_lower else "status"

    results = {"total": 0, "success": 0, "errors": 0, "details": []}
    valid_statuses = {"active", "locked", "closed", "maintenance"}

    for row in reader:
        # Normalize keys to lowercase
        row = {k.strip().lower(): v.strip() for k, v in row.items()}
        results["total"] += 1

        email = row.get("email", "").strip()
        new_status = row.get(status_col, "").strip().lower()

        if not email:
            results["errors"] += 1
            results["details"].append({"row": results["total"], "email": "", "error": "Empty email"})
            continue

        if new_status not in valid_statuses:
            results["errors"] += 1
            results["details"].append({
                "row": results["total"], "email": email,
                "error": f"Invalid status '{new_status}'"
            })
            continue

        acct = db.query(Account).filter(Account.email == email).first()
        if not acct:
            results["errors"] += 1
            results["details"].append({
                "row": results["total"], "email": email,
                "error": "Account not found"
            })
            continue

        if acct.account_status == new_status:
            results["details"].append({
                "row": results["total"], "email": email,
                "status": "skipped", "message": f"Already {new_status}"
            })
            continue

        try:
            await services.change_account_status(
                db, acct.id, new_status, admin_user=user.username
            )
            results["success"] += 1
            results["details"].append({
                "row": results["total"], "email": email, "status": "success",
                "message": f"{acct.account_status} -> {new_status}"
            })
        except ValueError as e:
            results["errors"] += 1
            results["details"].append({
                "row": results["total"], "email": email, "error": str(e)
            })

    cache.invalidate_all()
    return results


# ── Sync ──────────────────────────────────────────────────────────────

@app.post("/api/sync")
async def trigger_sync(
    domain: str = Query(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sync_status = cache.get_sync_status()
    if sync_status and sync_status.get("status") == "running":
        raise HTTPException(409, "A sync is already in progress")
    try:
        result = await services.sync_accounts(db, domain)
        return {"message": "Sync completed", "result": result}
    except Exception as e:
        logger.error("Sync failed: %s", e)
        raise HTTPException(500, "Sync failed — check server logs for details")


@app.get("/api/sync/status")
def sync_status(user: User = Depends(get_current_user)):
    status = cache.get_sync_status()
    return status or {"status": "idle"}


@app.get("/api/sync/history")
def sync_history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(SyncLog).order_by(SyncLog.started_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "logs": [
            {
                "id": l.id,
                "sync_type": l.sync_type,
                "status": l.status,
                "records_processed": l.records_processed,
                "records_added": l.records_added,
                "records_updated": l.records_updated,
                "errors": l.errors,
                "started_at": str(l.started_at) if l.started_at else None,
                "completed_at": str(l.completed_at) if l.completed_at else None,
            }
            for l in logs
        ],
        "total": total,
    }


# ── Domains ───────────────────────────────────────────────────────────

@app.get("/api/domains")
def list_domains(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domains = db.query(Domain).order_by(Domain.domain_name).all()
    return [
        {
            "id": d.id,
            "domain_name": d.domain_name,
            "account_count": d.account_count,
            "last_synced": str(d.last_synced) if d.last_synced else None,
        }
        for d in domains
    ]


# ── Audit Log ─────────────────────────────────────────────────────────

@app.get("/api/audit")
def audit_log(
    target: str = Query(None),
    action: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return services.get_audit_log(db, target, action, page, per_page)


# ── Health ────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}
