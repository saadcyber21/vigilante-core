from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import get_settings
from .db import get_db, init_db
from .models import Alert, AuditEvent, Case, User
from .security import current_user, hash_password, verify_password, create_token, require_roles
from .triage import fingerprint, triage

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with next(get_db()) as db:
        if not db.scalar(select(User).where(User.username == settings.admin_username)):
            db.add(User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            ))
            db.commit()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str


class WebhookRequest(BaseModel):
    payload: dict[str, Any]
    source_severity: str | None = None
    tenant_id: str = "default"
    idempotency_key: str | None = Field(default=None, max_length=250)


class AlertCreate(BaseModel):
    payload: dict[str, Any]
    source_key: str = "analyst"
    source_severity: str | None = None
    tenant_id: str = "default"
    idempotency_key: str | None = None


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=250)
    description: str = ""
    priority: str = "medium"
    alert_ids: list[str] = []


class CaseUpdate(BaseModel):
    status: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
    resolution: str | None = None
    title: str | None = None
    description: str | None = None


def audit(db: Session, user: User | None, action: str, resource_type: str, resource_id: str | None, metadata: dict | None = None) -> None:
    db.add(AuditEvent(
        actor_user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata or {},
    ))


def create_alert(db: Session, request: AlertCreate) -> tuple[Alert, bool]:
    key = request.idempotency_key or fingerprint(request.payload)
    existing = db.scalar(select(Alert).where(
        Alert.source_key == request.source_key,
        Alert.idempotency_key == key,
    ))
    if existing:
        return existing, False

    result = triage(request.payload, request.source_severity)
    alert = Alert(
        tenant_id=request.tenant_id,
        source_key=request.source_key,
        idempotency_key=key,
        fingerprint=fingerprint(request.payload),
        source_severity=request.source_severity,
        ai_severity=result["severity"],
        ai_confidence=result["confidence"],
        anomaly_score=result["anomaly_score"],
        threat_score=result["threat_score"],
        false_positive_score=result["false_positive_score"],
        ai_summary=result["summary"],
        ai_evidence=result["evidence"],
        payload=request.payload,
    )
    db.add(alert)
    db.flush()
    audit(db, None, "alert.created", "alert", alert.id, {"source": request.source_key})
    audit(db, None, "triage.completed", "alert", alert.id, {
        "severity": result["severity"],
        "model": result["model_metadata"]["model"],
    })
    db.commit()
    db.refresh(alert)
    return alert, True


def alert_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "tenant_id": a.tenant_id,
        "source_key": a.source_key,
        "status": a.status,
        "source_severity": a.source_severity,
        "ai_severity": a.ai_severity,
        "ai_confidence": a.ai_confidence,
        "anomaly_score": a.anomaly_score,
        "threat_score": a.threat_score,
        "false_positive_score": a.false_positive_score,
        "ai_summary": a.ai_summary,
        "ai_evidence": a.ai_evidence,
        "payload": a.payload,
        "case_id": a.case_id,
        "received_at": a.received_at,
    }


@app.get("/api/v1/health/live")
def liveness():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
def readiness(db: Session = Depends(get_db)):
    db.execute(select(func.count(User.id)))
    return {"status": "ready"}


@app.post("/api/v1/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        audit(db, user, "login.failed", "user", user.id if user else None)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    audit(db, user, "login.succeeded", "user", user.id)
    db.commit()
    return {"access_token": create_token(user), "token_type": "bearer", "expires_in": settings.jwt_expire_minutes * 60}


@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@app.post("/api/v1/ingest/webhooks/{source_key}", status_code=202)
def ingest_webhook(
    source_key: str,
    body: WebhookRequest,
    x_webhook_secret: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if source_key == "default" and not x_webhook_secret:
        raise HTTPException(status_code=401, detail="Webhook authentication required")
    if x_webhook_secret and x_webhook_secret != settings.webhook_secret:
        raise HTTPException(status_code=401, detail="Invalid webhook authentication")
    if len(str(body.payload).encode()) > settings.max_payload_bytes:
        raise HTTPException(status_code=413, detail="Payload too large")
    alert, created = create_alert(db, AlertCreate(
        payload=body.payload,
        source_key=source_key,
        source_severity=body.source_severity,
        tenant_id=body.tenant_id,
        idempotency_key=body.idempotency_key,
    ))
    return {"alert_id": alert.id, "accepted": created, "status": alert.status}


@app.post("/api/v1/ingest/syslog/test")
def parse_syslog(message: str, user: User = Depends(current_user)):
    parts = message.split(" ", 5)
    if len(parts) < 6:
        raise HTTPException(status_code=422, detail="Expected RFC3164-like syslog message")
    return {
        "facility_severity": parts[0],
        "timestamp": parts[1],
        "host": parts[2],
        "app": parts[3],
        "pid": parts[4],
        "message": parts[5],
    }


@app.post("/api/v1/alerts")
def create_alert_endpoint(body: AlertCreate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    alert, created = create_alert(db, body)
    audit(db, user, "alert.created.by_user", "alert", alert.id)
    db.commit()
    return {"created": created, "alert": alert_dict(alert)}


@app.get("/api/v1/alerts")
def list_alerts(
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))
    if severity:
        query = query.where(Alert.ai_severity == severity)
        count_query = count_query.where(Alert.ai_severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
        count_query = count_query.where(Alert.status == status_filter)
    total = db.scalar(count_query) or 0
    items = db.scalars(query.order_by(Alert.received_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {
        "items": [alert_dict(x) for x in items],
        "page": page,
        "page_size": page_size,
        "total": total,
        "next_page": page + 1 if page * page_size < total else None,
    }


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_dict(alert)


@app.post("/api/v1/alerts/{alert_id}/severity")
def override_severity(alert_id: str, severity: str, reason: str, db: Session = Depends(get_db), user: User = Depends(require_roles("analyst", "manager"))):
    if severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=422, detail="Invalid severity")
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.ai_severity = severity
    audit(db, user, "alert.severity_overridden", "alert", alert.id, {"reason": reason, "severity": severity})
    db.commit()
    return alert_dict(alert)


@app.post("/api/v1/cases")
def create_case(body: CaseCreate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.priority not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=422, detail="Invalid priority")
    case = Case(
        title=body.title,
        description=body.description,
        priority=body.priority,
        created_by=user.id,
    )
    db.add(case)
    db.flush()
    for alert_id in body.alert_ids:
        alert = db.get(Alert, alert_id)
        if alert:
            alert.case_id = case.id
    audit(db, user, "case.created", "case", case.id)
    db.commit()
    db.refresh(case)
    return case_dict(case)


def case_dict(case: Case) -> dict:
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "priority": case.priority,
        "assigned_to": case.assigned_to,
        "created_by": case.created_by,
        "resolution": case.resolution,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "alert_ids": [a.id for a in case.alerts],
    }


@app.get("/api/v1/cases")
def list_cases(db: Session = Depends(get_db), _: User = Depends(current_user)):
    cases = db.scalars(select(Case).order_by(Case.updated_at.desc())).all()
    return {"items": [case_dict(x) for x in cases], "page": 1, "page_size": len(cases), "total": len(cases), "next_page": None}


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_dict(case)


@app.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(case, field, value)
    case.updated_at = datetime.now(timezone.utc)
    audit(db, user, "case.updated", "case", case.id)
    db.commit()
    db.refresh(case)
    return case_dict(case)


@app.get("/api/v1/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), _: User = Depends(current_user)):
    def count(value):
        return db.scalar(select(func.count(Alert.id)).where(Alert.ai_severity == value)) or 0
    return {
        "alerts_total": db.scalar(select(func.count(Alert.id))) or 0,
        "cases_total": db.scalar(select(func.count(Case.id))) or 0,
        "alerts_by_severity": {level: count(level) for level in ("low", "medium", "high", "critical")},
        "open_cases": db.scalar(select(func.count(Case.id)).where(Case.status.in_(["open", "in_progress"]))) or 0,
    }


@app.get("/api/v1/audit-events")
def audit_events(db: Session = Depends(get_db), _: User = Depends(require_roles("auditor", "security_admin"))):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(200)).all()
    return [{
        "id": e.id,
        "action": e.action,
        "resource_type": e.resource_type,
        "resource_id": e.resource_id,
        "actor_user_id": e.actor_user_id,
        "metadata": e.metadata_json,
        "success": e.success,
        "occurred_at": e.occurred_at,
    } for e in events]


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Vigilante AI</title>
<style>
body{font-family:system-ui;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}
main{max-width:1100px;margin:auto}button{background:#2563eb;color:white;border:0;border-radius:5px;padding:.6rem 1rem;cursor:pointer}
input{padding:.6rem;margin:.25rem;background:#1e293b;color:white;border:1px solid #475569;border-radius:4px}
.card{background:#1e293b;padding:1rem;border-radius:8px;margin:1rem 0}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
table{width:100%;border-collapse:collapse}td,th{padding:.6rem;border-bottom:1px solid #475569;text-align:left}
.low{color:#86efac}.medium{color:#fde047}.high{color:#fb923c}.critical{color:#f87171}
</style></head>
<body><main><h1>Vigilante AI</h1>
<section class="card"><input id="user" value="admin"><input id="pass" type="password" value="change-me"><button onclick="login()">Login</button><span id="auth"></span></section>
<section class="grid" id="summary"></section>
<section class="card"><h2>Alert queue</h2><table><thead><tr><th>Severity</th><th>Summary</th><th>Source</th><th>Received</th></tr></thead><tbody id="alerts"></tbody></table></section>
<script>
let token="";
async function login(){let r=await fetch("/api/v1/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user.value,password:pass.value})});let x=await r.json();if(r.ok){token=x.access_token;auth.textContent=" authenticated";load()}else auth.textContent=x.detail}
async function api(path){return (await fetch(path,{headers:{Authorization:"Bearer "+token}})).json()}
async function load(){let s=await api("/api/v1/dashboard/summary");summary.innerHTML=Object.entries(s).filter(([k])=>k!="alerts_by_severity").map(([k,v])=>`<div class=card><b>${k}</b><h2>${v}</h2></div>`).join("");let a=await api("/api/v1/alerts");alerts.innerHTML=a.items.map(x=>`<tr><td class=${x.ai_severity}>${x.ai_severity}</td><td>${x.ai_summary||""}</td><td>${x.source_key}</td><td>${new Date(x.received_at).toLocaleString()}</td></tr>`).join("")}
</script></main></body></html>
"""
