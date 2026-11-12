from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hmac
import json
import re
from pathlib import Path
from typing import Any, Literal
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .config import get_settings
from .db import SessionLocal, get_db, init_db
from .models import Alert, AuditEvent, Case, InvestigationRun, ResponseProposal, User
from .security import current_user, hash_password, verify_password, create_token, require_roles
from .triage import fingerprint, triage
from .investigation import build_investigation
from .middleware import RequestBodySizeLimitMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.username == settings.admin_username)):
            db.add(User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            ))
            db.commit()
    yield


app = FastAPI(title=settings.app_name, version="0.3.0", lifespan=lifespan)
app.add_middleware(RequestBodySizeLimitMiddleware, max_bytes=settings.max_payload_bytes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Webhook-Secret"],
)

ROOT_DIR = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=ROOT_DIR / "docs" / "static"), name="static")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class WebhookRequest(StrictModel):
    payload: dict[str, Any]
    source_severity: Literal["low", "medium", "high", "critical"] | None = None
    idempotency_key: str | None = Field(default=None, max_length=250)


class AlertCreate(StrictModel):
    payload: dict[str, Any]
    source_key: str = Field(default="analyst", min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
    source_severity: Literal["low", "medium", "high", "critical"] | None = None
    idempotency_key: str | None = Field(default=None, max_length=250)


class AlertStatusUpdate(StrictModel):
    status: Literal["new", "triaged", "investigating", "contained", "resolved", "closed"]
    reason: str = Field(min_length=3, max_length=2_000)


class UserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@+-]*$")
    password: str = Field(min_length=16, max_length=256)
    role: Literal["analyst", "manager", "auditor", "security_admin"] = "analyst"

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()


class UserStatusUpdate(StrictModel):
    is_active: bool


class CaseCreate(StrictModel):
    title: str = Field(min_length=1, max_length=250)
    description: str = Field(default="", max_length=10_000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=100)


class CaseUpdate(StrictModel):
    status: Literal["open", "in_progress", "contained", "resolved", "closed"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    assigned_to: str | None = Field(default=None, max_length=36)
    resolution: str | None = Field(default=None, max_length=10_000)
    title: str | None = Field(default=None, min_length=1, max_length=250)
    description: str | None = Field(default=None, max_length=10_000)


class ResponseProposalCreate(StrictModel):
    action_type: Literal["disable_account", "isolate_host", "revoke_credential", "block_indicator", "escalate_incident"]
    target_reference: str = Field(min_length=1, max_length=250)
    rationale: str = Field(min_length=8, max_length=2_000)


class ResponseReview(StrictModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=3, max_length=2_000)


class InvestigationFeedback(StrictModel):
    rating: int = Field(ge=1, le=5)
    note: str = Field(default="", max_length=2_000)


def audit(
    db: Session,
    user: User | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    metadata: dict | None = None,
    *,
    success: bool = True,
    actor_type: str | None = None,
) -> None:
    db.add(AuditEvent(
        actor_user_id=user.id if user else None,
        actor_type=actor_type or ("user" if user else "system"),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata or {},
        success=success,
    ))


def create_alert(db: Session, request: AlertCreate, actor: User | None = None) -> tuple[Alert, bool]:
    key = request.idempotency_key or fingerprint(request.payload)
    existing = db.scalar(select(Alert).where(
        Alert.tenant_id == settings.tenant_id,
        Alert.source_key == request.source_key,
        Alert.idempotency_key == key,
    ))
    if existing:
        return existing, False

    result = triage(request.payload, request.source_severity)
    alert = Alert(
        tenant_id=settings.tenant_id,
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
    audit(db, actor, "alert.created", "alert", alert.id, {"source": request.source_key}, actor_type="user" if actor else "integration")
    audit(db, None, "triage.completed", "alert", alert.id, {
        "severity": result["severity"],
        "model": result["model_metadata"]["model"],
    })
    db.commit()
    db.refresh(alert)
    return alert, True


def alert_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "tenant_id": alert.tenant_id,
        "source_key": alert.source_key,
        "status": alert.status,
        "source_severity": alert.source_severity,
        "ai_severity": alert.ai_severity,
        "ai_confidence": alert.ai_confidence,
        "anomaly_score": alert.anomaly_score,
        "threat_score": alert.threat_score,
        "false_positive_score": alert.false_positive_score,
        "ai_summary": alert.ai_summary,
        "ai_evidence": alert.ai_evidence,
        "payload": alert.payload,
        "case_id": alert.case_id,
        "received_at": alert.received_at,
    }


def user_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
    }


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
        "alert_ids": [alert.id for alert in case.alerts],
    }


def response_proposal_dict(proposal: ResponseProposal) -> dict:
    return {
        "id": proposal.id,
        "alert_id": proposal.alert_id,
        "action_type": proposal.action_type,
        "target_reference": proposal.target_reference,
        "rationale": proposal.rationale,
        "status": proposal.status,
        "proposed_by": proposal.proposed_by,
        "reviewed_by": proposal.reviewed_by,
        "review_reason": proposal.review_reason,
        "created_at": proposal.created_at,
        "reviewed_at": proposal.reviewed_at,
        "execution_status": "not_executed",
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
        audit(
            db,
            user,
            "login.failed",
            "user",
            user.id if user else None,
            {"username": body.username},
            success=False,
            actor_type="user" if user else "anonymous",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    audit(db, user, "login.succeeded", "user", user.id)
    db.commit()
    return {"access_token": create_token(user), "token_type": "bearer", "expires_in": settings.jwt_expire_minutes * 60}


@app.get("/api/v1/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@app.get("/api/v1/admin/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_roles("security_admin"))):
    users = db.scalars(select(User).order_by(User.created_at.asc())).all()
    return {"items": [user_dict(user) for user in users]}


@app.post("/api/v1/admin/users", status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, db: Session = Depends(get_db), actor: User = Depends(require_roles("security_admin"))):
    username = body.username.strip().lower()
    if db.scalar(select(User).where(func.lower(User.username) == username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists")
    audit(db, actor, "user.created", "user", user.id, {"role": user.role})
    db.commit()
    db.refresh(user)
    return user_dict(user)


@app.patch("/api/v1/admin/users/{user_id}")
def update_user_status(
    user_id: str,
    body: UserStatusUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("security_admin")),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == actor.id and not body.is_active:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account")
    if user.role == "admin" and not body.is_active:
        active_admins = db.scalar(select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="The last active administrator cannot be deactivated")
    user.is_active = body.is_active
    audit(db, actor, "user.activated" if body.is_active else "user.deactivated", "user", user.id)
    db.commit()
    db.refresh(user)
    return user_dict(user)


@app.post("/api/v1/ingest/webhooks/{source_key}", status_code=status.HTTP_202_ACCEPTED)
def ingest_webhook(
    source_key: str,
    body: WebhookRequest,
    x_webhook_secret: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", source_key):
        raise HTTPException(status_code=422, detail="Invalid source key")
    expected_secret = settings.webhook_secret_for(source_key)
    if not expected_secret or not x_webhook_secret or not hmac.compare_digest(expected_secret, x_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook authentication")
    payload_bytes = json.dumps(body.payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload_bytes) > settings.max_payload_bytes:
        raise HTTPException(status_code=413, detail="Payload too large")
    alert, created = create_alert(db, AlertCreate(
        payload=body.payload,
        source_key=source_key,
        source_severity=body.source_severity,
        idempotency_key=body.idempotency_key,
    ))
    return {"alert_id": alert.id, "accepted": created, "status": alert.status}


@app.post("/api/v1/ingest/syslog/test")
def parse_syslog(message: str, _: User = Depends(current_user)):
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
def create_alert_endpoint(body: AlertCreate, db: Session = Depends(get_db), user: User = Depends(require_roles("analyst", "manager", "security_admin"))):
    alert, created = create_alert(db, body, actor=user)
    return {"created": created, "alert": alert_dict(alert)}


@app.get("/api/v1/alerts")
def list_alerts(
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    status_filter: Literal["new", "triaged", "investigating", "contained", "resolved", "closed"] | None = Query(default=None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
):
    filters = [Alert.tenant_id == settings.tenant_id]
    if severity:
        filters.append(Alert.ai_severity == severity)
    if status_filter:
        filters.append(Alert.status == status_filter)
    query = select(Alert).where(*filters)
    count_query = select(func.count(Alert.id)).where(*filters)
    total = db.scalar(count_query) or 0
    items = db.scalars(query.order_by(Alert.received_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {
        "items": [alert_dict(alert) for alert in items],
        "page": page,
        "page_size": page_size,
        "total": total,
        "next_page": page + 1 if page * page_size < total else None,
    }


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == settings.tenant_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_dict(alert)


@app.post("/api/v1/alerts/{alert_id}/investigation")
def investigate_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == settings.tenant_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not settings.llm_enabled or not settings.llm_api_key or not settings.llm_model or not settings.llm_base_url:
        raise HTTPException(status_code=503, detail="AI investigation is not configured. Set LLM_ENABLED=true, LLM_BASE_URL, LLM_API_KEY, and LLM_MODEL on the API server.")
    try:
        brief = build_investigation(alert.payload, alert.ai_summary, alert.ai_severity,
                                    settings.llm_base_url, settings.llm_api_key, settings.llm_model)
    except RuntimeError as exc:
        audit(db, user, "investigation.failed", "alert", alert.id, {"provider": settings.llm_provider})
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit(db, user, "investigation.generated", "alert", alert.id, {
        "provider": settings.llm_provider, "model": settings.llm_model,
        "confidence": brief["confidence"], "evidence_count": len(brief["evidence"]),
    })
    run = InvestigationRun(
        tenant_id=settings.tenant_id,
        alert_id=alert.id,
        created_by=user.id,
        provider=settings.llm_provider,
        model=settings.llm_model,
        result_json=brief,
    )
    db.add(run)
    db.flush()
    db.commit()
    return {
        "investigation_id": run.id,
        "alert_id": alert.id,
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "brief": brief,
        "data_notice": "This alert's summary and payload were sent to the AI provider configured by this API operator. Treat the output as advisory; validate evidence before acting.",
        "execution_status": "not_executed",
    }


@app.post("/api/v1/investigations/{investigation_id}/feedback")
def submit_investigation_feedback(
    investigation_id: str,
    body: InvestigationFeedback,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    run = db.scalar(select(InvestigationRun).where(
        InvestigationRun.id == investigation_id,
        InvestigationRun.tenant_id == settings.tenant_id,
    ))
    if not run:
        raise HTTPException(status_code=404, detail="Investigation not found")
    run.rating = body.rating
    run.feedback_note = body.note.strip()
    run.feedback_by = user.id
    run.feedback_at = datetime.now(timezone.utc)
    audit(db, user, "investigation.feedback_submitted", "investigation", run.id, {
        "rating": body.rating,
        "has_note": bool(run.feedback_note),
    })
    db.commit()
    return {"investigation_id": run.id, "rating": run.rating, "feedback_recorded": True}


@app.get("/api/v1/ai/quality")
def ai_quality_metrics(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("auditor", "security_admin", "manager")),
):
    total = db.scalar(select(func.count(InvestigationRun.id)).where(InvestigationRun.tenant_id == settings.tenant_id)) or 0
    rated = db.scalar(select(func.count(InvestigationRun.id)).where(
        InvestigationRun.tenant_id == settings.tenant_id,
        InvestigationRun.rating.is_not(None),
    )) or 0
    average = db.scalar(select(func.avg(InvestigationRun.rating)).where(
        InvestigationRun.tenant_id == settings.tenant_id,
        InvestigationRun.rating.is_not(None),
    ))
    return {
        "investigation_runs": total,
        "rated_runs": rated,
        "average_rating": round(float(average), 2) if average is not None else None,
        "rating_scale": "1=not useful, 5=useful",
        "note": "Analyst feedback is an evaluation signal; it does not automatically train or update a model.",
    }


@app.post("/api/v1/alerts/{alert_id}/severity")
def override_severity(
    alert_id: str,
    severity: Literal["low", "medium", "high", "critical"],
    reason: str = Query(min_length=3, max_length=2_000),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == settings.tenant_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.ai_severity = severity
    audit(db, user, "alert.severity_overridden", "alert", alert.id, {"reason": reason, "severity": severity})
    db.commit()
    return alert_dict(alert)


@app.patch("/api/v1/alerts/{alert_id}")
def update_alert_status(
    alert_id: str,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == settings.tenant_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    previous_status = alert.status
    alert.status = body.status
    audit(db, user, "alert.status_updated", "alert", alert.id, {
        "from": previous_status,
        "to": body.status,
        "reason": body.reason.strip(),
    })
    db.commit()
    db.refresh(alert)
    return alert_dict(alert)


@app.post("/api/v1/cases")
def create_case(
    body: CaseCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    requested_ids = set(body.alert_ids)
    alerts = []
    if requested_ids:
        alerts = db.scalars(select(Alert).where(
            Alert.id.in_(requested_ids),
            Alert.tenant_id == settings.tenant_id,
        )).all()
        if len(alerts) != len(requested_ids):
            raise HTTPException(status_code=404, detail="One or more alerts were not found")
        if any(alert.case_id for alert in alerts):
            raise HTTPException(status_code=409, detail="An alert is already linked to a case")

    next_case_number = (db.scalar(select(func.max(Case.case_number))) or 0) + 1
    case = Case(
        case_number=next_case_number,
        title=body.title.strip(),
        description=body.description,
        priority=body.priority,
        created_by=user.id,
    )
    db.add(case)
    db.flush()
    for alert in alerts:
        alert.case_id = case.id
    audit(db, user, "case.created", "case", case.id, {"alert_count": len(alerts)})
    db.commit()
    db.refresh(case)
    return case_dict(case)


@app.get("/api/v1/cases")
def list_cases(db: Session = Depends(get_db), _: User = Depends(current_user)):
    cases = db.scalars(select(Case).order_by(Case.updated_at.desc())).all()
    return {"items": [case_dict(case) for case in cases], "page": 1, "page_size": len(cases), "total": len(cases), "next_page": None}


@app.get("/api/v1/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_dict(case)


@app.patch("/api/v1/cases/{case_id}")
def update_case(
    case_id: str,
    body: CaseUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="At least one case field is required")
    if "assigned_to" in updates and updates["assigned_to"] is not None:
        assignee = db.get(User, updates["assigned_to"])
        if not assignee or not assignee.is_active:
            raise HTTPException(status_code=422, detail="Assignee must be an active user")
    for field, value in updates.items():
        setattr(case, field, value)
    case.updated_at = datetime.now(timezone.utc)
    audit(db, user, "case.updated", "case", case.id, {"fields": sorted(updates)})
    db.commit()
    db.refresh(case)
    return case_dict(case)


@app.post("/api/v1/alerts/{alert_id}/response-proposals", status_code=status.HTTP_201_CREATED)
def create_response_proposal(
    alert_id: str,
    body: ResponseProposalCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("analyst", "manager", "security_admin")),
):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == settings.tenant_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    proposal = ResponseProposal(
        alert_id=alert.id,
        action_type=body.action_type,
        target_reference=body.target_reference.strip(),
        rationale=body.rationale.strip(),
        proposed_by=user.id,
    )
    db.add(proposal)
    db.flush()
    audit(db, user, "response.proposed", "response_proposal", proposal.id, {
        "alert_id": alert.id,
        "action_type": proposal.action_type,
        "execution_status": "not_executed",
    })
    db.commit()
    db.refresh(proposal)
    return response_proposal_dict(proposal)


@app.get("/api/v1/response-proposals")
def list_response_proposals(
    status_filter: Literal["pending", "approved", "rejected"] | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
):
    query = select(ResponseProposal)
    if status_filter:
        query = query.where(ResponseProposal.status == status_filter)
    proposals = db.scalars(query.order_by(ResponseProposal.created_at.desc())).all()
    return {"items": [response_proposal_dict(proposal) for proposal in proposals]}


@app.post("/api/v1/response-proposals/{proposal_id}/review")
def review_response_proposal(
    proposal_id: str,
    body: ResponseReview,
    db: Session = Depends(get_db),
    reviewer: User = Depends(require_roles("manager", "security_admin")),
):
    proposal = db.get(ResponseProposal, proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail="Response proposal not found")
    if proposal.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending proposals can be reviewed")
    if proposal.proposed_by == reviewer.id:
        raise HTTPException(status_code=409, detail="A different user must review this proposal")
    proposal.status = "approved" if body.decision == "approve" else "rejected"
    proposal.reviewed_by = reviewer.id
    proposal.review_reason = body.reason.strip()
    proposal.reviewed_at = datetime.now(timezone.utc)
    audit(db, reviewer, f"response.{proposal.status}", "response_proposal", proposal.id, {
        "action_type": proposal.action_type,
        "execution_status": "not_executed",
        "reason": proposal.review_reason,
    })
    db.commit()
    db.refresh(proposal)
    return response_proposal_dict(proposal)


@app.get("/api/v1/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), _: User = Depends(current_user)):
    def count(value):
        return db.scalar(select(func.count(Alert.id)).where(Alert.tenant_id == settings.tenant_id, Alert.ai_severity == value)) or 0
    return {
        "alerts_total": db.scalar(select(func.count(Alert.id)).where(Alert.tenant_id == settings.tenant_id)) or 0,
        "cases_total": db.scalar(select(func.count(Case.id))) or 0,
        "alerts_by_severity": {level: count(level) for level in ("low", "medium", "high", "critical")},
        "open_cases": db.scalar(select(func.count(Case.id)).where(Case.status.in_(["open", "in_progress"]))) or 0,
    }


@app.get("/api/v1/audit-events")
def audit_events(db: Session = Depends(get_db), _: User = Depends(require_roles("auditor", "security_admin"))):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(200)).all()
    return [{
        "id": event.id,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "actor_user_id": event.actor_user_id,
        "actor_type": event.actor_type,
        "metadata": event.metadata_json,
        "success": event.success,
        "occurred_at": event.occurred_at,
    } for event in events]


@app.get("/")
def dashboard():
    return FileResponse(ROOT_DIR / "docs" / "index.html")
