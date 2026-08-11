# app/main.py
import math
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import case
from sqlalchemy import func as sql_func
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from .analytics import initialize_analytics_objects, initialize_timescale_storage
from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .crypto import decrypt, encrypt
from .db import Base, SessionLocal, engine, get_db
from .ingest import delete_connection_data, process_wazuh_vulnerabilities
from .migrations import POST, PRE, run_migrations
from .models import (
    AgentGroup,
    Asset,
    AssetGroupMember,
    FindingHistory,
    OperatingSystem,
    Package,
    SEVERITY_RANKS,
    User,
    VulnerabilityCatalog,
    VulnerabilityDetection,
    VulnerabilityFinding,
    WazuhConnection,
)
from .wazuh_client import fetch_all_vulns, test_connection

# --- Arranque: migrar esquema antiguo -> crear tablas -> copiar datos --------
run_migrations(engine, PRE)
Base.metadata.create_all(bind=engine)
run_migrations(engine, POST)
initialize_timescale_storage(engine)
initialize_analytics_objects(engine)

CONNECTION_NOT_FOUND = "Conexión no encontrada"
VULN_NOT_FOUND = "Vulnerabilidad no encontrada"

# ---------------------------------------------------------------------------
# Registro de trabajos de sincronización en segundo plano (progreso + toast)
# ---------------------------------------------------------------------------
SYNC_JOBS: dict = {}
SYNC_JOBS_LOCK = threading.Lock()
MAX_SYNC_JOBS = 20

# En tests (o entornos sin worker) ejecuta la sincronización de forma síncrona
# en la misma sesión de la petición, en vez de lanzar un hilo.
SYNC_INLINE = os.getenv("SYNC_INLINE", "").strip().lower() in ("1", "true", "yes")


def _new_sync_job() -> str:
    job_id = str(uuid.uuid4())
    with SYNC_JOBS_LOCK:
        if len(SYNC_JOBS) >= MAX_SYNC_JOBS:
            oldest = sorted(SYNC_JOBS.items(), key=lambda kv: kv[1]["started_at"])
            for old_id, _ in oldest[: len(SYNC_JOBS) - MAX_SYNC_JOBS + 1]:
                SYNC_JOBS.pop(old_id, None)
        SYNC_JOBS[job_id] = {
            "job_id": job_id,
            "status": "pending",  # pending | running | completed | error
            "phase": "En cola",
            "total": 0,
            "processed": 0,
            "synced": 0,
            "connections_done": 0,
            "connections_total": 0,
            "current_connection": None,
            "results": [],
            "error": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }
    return job_id


def _update_sync_job(job_id: str, **fields) -> None:
    with SYNC_JOBS_LOCK:
        job = SYNC_JOBS.get(job_id)
        if job:
            job.update(fields)


class WazuhConnectionRequest(BaseModel):
    name: str
    indexer_url: str
    wazuh_user: str
    wazuh_password: str


def _initial_admin_credentials() -> tuple[str, str]:
    username = os.getenv("INITIAL_ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.getenv("INITIAL_ADMIN_PASSWORD")
    if password:
        return username, password
    if os.getenv("APP_ENV", "development").lower() == "production":
        raise RuntimeError("INITIAL_ADMIN_PASSWORD debe estar definida en produccion")
    return username, "admin"


def create_default_admin():
    username, password = _initial_admin_credentials()
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == username).first():
            print(f"Creando usuario administrador inicial: {username}")
            db.add(User(
                username=username,
                password_hash=hash_password(password),
                is_active=True,
                is_default_password=True,
            ))
            db.commit()
    finally:
        db.close()


create_default_admin()

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ---------------------------------------------------------------------------
# Autenticación y usuarios
# ---------------------------------------------------------------------------
@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    return {
        "access_token": create_access_token(data={"sub": user.username}),
        "token_type": "bearer",
    }


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


def validate_strong_password(password: str) -> None:
    """Valida que la contraseña sea robusta. Lanza HTTPException si no cumple."""
    errors = []
    if len(password) < 8:
        errors.append("mínimo 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("al menos una letra mayúscula")
    if not re.search(r"[a-z]", password):
        errors.append("al menos una letra minúscula")
    if not re.search(r"\d", password):
        errors.append("al menos un número")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        errors.append("al menos un carácter especial (!@#$%^&*...)")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"La contraseña no es suficientemente robusta: {', '.join(errors)}",
        )


@app.post("/auth/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña antigua es incorrecta")
    if request.old_password == request.new_password:
        raise HTTPException(
            status_code=400, detail="La nueva contraseña debe ser diferente a la anterior"
        )
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas nuevas no coinciden")

    validate_strong_password(request.new_password)

    current_user.password_hash = hash_password(request.new_password)
    current_user.is_active = True
    current_user.is_default_password = False
    db.add(current_user)
    db.commit()
    return {"message": "Contraseña actualizada exitosamente"}


@app.get("/users/me")
def get_user_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_active": current_user.is_active,
        "is_default_password": current_user.is_default_password,
    }


class NewUserRequest(BaseModel):
    username: str
    password: str


@app.post("/users")
def create_user(
    request: NewUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.username == request.username).first():
        raise HTTPException(
            status_code=400, detail="El nombre de usuario ya esta ocupado. Elige otro."
        )
    db.add(User(
        username=request.username,
        password_hash=hash_password(request.password),
        is_default_password=True,
    ))
    db.commit()
    return {"message": "Usuario creado"}


@app.get("/users")
def list_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return [{"id": u.id, "username": u.username} for u in db.query(User).all()]


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado"}


# ---------------------------------------------------------------------------
# Conexiones Wazuh
# ---------------------------------------------------------------------------
@app.get("/wazuh-connections")
def list_connections(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return [
        {
            "id": c.id,
            "name": c.name,
            "indexer_url": c.indexer_url,
            "wazuh_user": c.wazuh_user,
            "is_active": c.is_active,
            "tested": c.tested,
            "last_tested_at": c.last_tested_at,
            "last_test_ok": c.last_test_ok,
            "last_sync_at": c.last_sync_at,
        }
        for c in db.query(WazuhConnection).all()
    ]


@app.post("/wazuh-connections", status_code=201)
def create_connection(
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.query(WazuhConnection).filter(WazuhConnection.name == request.name).first():
        raise HTTPException(status_code=400, detail="Ya existe una conexión con ese nombre")

    if not test_connection(request.indexer_url, request.wazuh_user, request.wazuh_password):
        raise HTTPException(
            status_code=400,
            detail="No se pudo establecer conexión con el indexador Wazuh",
        )

    conn = WazuhConnection(
        name=request.name,
        indexer_url=request.indexer_url,
        wazuh_user=request.wazuh_user,
        wazuh_password=encrypt(request.wazuh_password),
        tested=True,
        last_tested_at=sql_func.now(),
        last_test_ok=True,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return {"message": "Conexión creada", "id": conn.id}


@app.put("/wazuh-connections/{conn_id}")
def update_connection(
    conn_id: int,
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    conn.name = request.name
    conn.indexer_url = request.indexer_url
    conn.wazuh_user = request.wazuh_user
    if request.wazuh_password:
        conn.wazuh_password = encrypt(request.wazuh_password)
    db.commit()
    return {"message": "Conexión actualizada"}


@app.delete("/wazuh-connections/{conn_id}")
def delete_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    delete_connection_data(db, conn_id)
    db.delete(conn)
    db.commit()
    return {"message": "Conexión eliminada"}


@app.post("/wazuh-connections/{conn_id}/test")
def test_wazuh_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    ok = test_connection(conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password))
    conn.tested = True
    conn.last_tested_at = sql_func.now()
    conn.last_test_ok = ok
    db.commit()
    return {"ok": ok, "message": "Conexión exitosa" if ok else "No se pudo conectar"}


@app.post("/wazuh-connections/{conn_id}/sync")
def sync_connection(
    conn_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)
    if not conn.is_active:
        raise HTTPException(status_code=400, detail="La conexión está inactiva")

    job_id = _start_sync_job([conn_id], db=db)
    with SYNC_JOBS_LOCK:
        job = dict(SYNC_JOBS.get(job_id, {}))
    return {
        "job_id": job_id,
        "status": job.get("status", "running"),
        "connection": conn.name,
        "synced": job.get("synced", 0),
        "results": job.get("results", []),
    }


# ---------------------------------------------------------------------------
# Worker de sincronización en segundo plano
# ---------------------------------------------------------------------------
def _run_sync_job(job_id: str, conn_ids: List[int], db=None) -> None:
    """Ejecuta la sincronización.

    Si se entrega ``db`` se usa esa sesión (modo inline/tests) y NO se cierra;
    en caso contrario crea su propia sesión (modo hilo en segundo plano).
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    _update_sync_job(
        job_id, status="running", phase="Iniciando", connections_total=len(conn_ids)
    )
    results = []
    total_synced = 0
    try:
        for index, conn_id in enumerate(conn_ids):
            conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
            if not conn:
                continue

            _update_sync_job(
                job_id,
                current_connection=conn.name,
                connections_done=index,
                phase=f"Descargando datos de {conn.name}",
                processed=0,
                total=0,
            )

            try:
                raw_vulns = fetch_all_vulns(
                    conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password)
                )
                _update_sync_job(
                    job_id, phase=f"Procesando {conn.name}", total=len(raw_vulns)
                )

                def _cb(done, total, _name=conn.name):
                    _update_sync_job(
                        job_id,
                        processed=done,
                        total=total,
                        phase=f"Procesando {_name} ({done}/{total})",
                    )

                count = process_wazuh_vulnerabilities(
                    db, conn.id, raw_vulns, progress_cb=_cb
                )
                db.commit()
                total_synced += count
                results.append({"connection": conn.name, "synced": count, "ok": True})
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                results.append({"connection": conn.name, "ok": False, "error": str(exc)})

            _update_sync_job(
                job_id,
                connections_done=index + 1,
                synced=total_synced,
                results=list(results),
            )

        _update_sync_job(
            job_id,
            status="completed",
            phase="Completado",
            current_connection=None,
            synced=total_synced,
            results=list(results),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        _update_sync_job(
            job_id,
            status="error",
            phase="Error",
            error=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
    finally:
        if own_session:
            db.close()


def _start_sync_job(conn_ids: List[int], db=None) -> str:
    job_id = _new_sync_job()
    _update_sync_job(job_id, connections_total=len(conn_ids))
    if SYNC_INLINE:
        _run_sync_job(job_id, conn_ids, db=db)
        return job_id
    threading.Thread(
        target=_run_sync_job, args=(job_id, conn_ids), daemon=True
    ).start()
    return job_id


@app.post("/vulns/sync-all")
def sync_all_connections(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active.is_(True)).all()
    if not conns:
        raise HTTPException(
            status_code=400, detail="No hay conexiones activas para sincronizar"
        )

    conn_ids = [c.id for c in conns]
    job_id = _start_sync_job(conn_ids, db=db)
    with SYNC_JOBS_LOCK:
        job = dict(SYNC_JOBS.get(job_id, {}))
    return {
        "job_id": job_id,
        "status": job.get("status", "running"),
        "connections_total": len(conn_ids),
        "synced": job.get("synced", 0),
        "results": job.get("results", []),
    }


@app.get("/sync/status")
def sync_status(
    job_id: Optional[str] = None, current_user: User = Depends(get_current_user)
):
    with SYNC_JOBS_LOCK:
        if job_id:
            job = SYNC_JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job no encontrado")
            return dict(job)
        if not SYNC_JOBS:
            return {"status": "idle", "job_id": None}
        return dict(max(SYNC_JOBS.values(), key=lambda j: j["started_at"]))


# ---------------------------------------------------------------------------
# Helpers de consulta
# ---------------------------------------------------------------------------
def _db_dialect(db: Session) -> str:
    return db.get_bind().dialect.name


def _is_postgres(db: Session) -> bool:
    return _db_dialect(db) == "postgresql"


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _split_int_csv(value: Optional[str]) -> List[int]:
    out = []
    for item in _split_csv(value):
        try:
            out.append(int(item))
        except ValueError:
            continue
    return out


# "resuelta" / "no resuelta" en cualquiera de sus formas -> estado canónico
_STATUS_ALIASES = {
    "active": "ACTIVE",
    "activa": "ACTIVE",
    "activas": "ACTIVE",
    "unresolved": "ACTIVE",
    "no_resuelta": "ACTIVE",
    "no-resuelta": "ACTIVE",
    "sin_resolver": "ACTIVE",
    "resolved": "RESOLVED",
    "resuelta": "RESOLVED",
    "resueltas": "RESOLVED",
}


def _normalize_status(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    key = value.strip().lower().replace(" ", "_")
    if key in ("all", "todas", "todos", ""):
        return None
    return _STATUS_ALIASES.get(key, value.strip().upper())


def _rank_from_severities(severities: List[str]) -> List[int]:
    return [SEVERITY_RANKS.get(s.capitalize(), 0) for s in severities]


_SORTABLE_COLUMNS = {
    "cve_id": VulnerabilityFinding.cve_id,
    "agent_name": Asset.hostname,
    "package_name": Package.name,
    "score_base": VulnerabilityFinding.score_base,
    "first_seen": VulnerabilityFinding.first_seen,
    "last_seen": VulnerabilityFinding.last_seen,
    "resolved_at": VulnerabilityFinding.resolved_at,
    "status": VulnerabilityFinding.status,
    "connection_name": WazuhConnection.name,
    "severity": VulnerabilityCatalog.severity_rank,
    "severity_rank": VulnerabilityCatalog.severity_rank,
}


def _finding_query(db: Session):
    """Consulta base con todos los joins del modelo en estrella."""
    return (
        db.query(
            VulnerabilityFinding,
            Asset,
            Package,
            VulnerabilityCatalog,
            WazuhConnection,
            OperatingSystem,
        )
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .join(Package, Package.id == VulnerabilityFinding.package_id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .join(WazuhConnection, WazuhConnection.id == Asset.connection_id)
        .outerjoin(OperatingSystem, OperatingSystem.id == Asset.os_id)
    )


class VulnFilters:
    """Todos los filtros de vulnerabilidades que expone la API."""

    def __init__(
        self,
        connection_id: Optional[int] = None,
        agent_name: Optional[str] = None,
        group: Optional[str] = None,
        group_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        package_name: Optional[str] = None,
        severity: Optional[str] = None,
        rank_min: Optional[int] = None,
        os_platform: Optional[str] = None,
        os_version: Optional[str] = None,
        status: Optional[str] = None,
        score_min: Optional[float] = None,
        score_max: Optional[float] = None,
        search: Optional[str] = None,
    ):
        self.connection_id = connection_id
        self.agents = _split_csv(agent_name)
        self.groups = _split_csv(group)
        self.group_ids = _split_int_csv(group_id)
        self.cves = _split_csv(cve_id)
        self.packages = _split_csv(package_name)
        self.severities = _split_csv(severity)
        self.rank_min = rank_min
        self.os_platforms = _split_csv(os_platform)
        self.os_versions = _split_csv(os_version)
        self.status = _normalize_status(status)
        self.score_min = score_min
        self.score_max = score_max
        self.search = search


def _apply_vuln_filters(query, f: VulnFilters):
    if f.connection_id:
        query = query.filter(Asset.connection_id == f.connection_id)
    if f.agents:
        query = query.filter(Asset.hostname.in_(f.agents))
    if f.cves:
        query = query.filter(VulnerabilityFinding.cve_id.in_(f.cves))
    if f.packages:
        query = query.filter(Package.name.in_(f.packages))
    if f.severities:
        query = query.filter(
            VulnerabilityCatalog.severity_rank.in_(_rank_from_severities(f.severities))
        )
    if f.rank_min is not None:
        query = query.filter(VulnerabilityCatalog.severity_rank >= f.rank_min)
    if f.os_platforms:
        query = query.filter(OperatingSystem.platform.in_(f.os_platforms))
    if f.os_versions:
        query = query.filter(OperatingSystem.version.in_(f.os_versions))
    if f.status:
        query = query.filter(VulnerabilityFinding.status == f.status)
    if f.score_min is not None:
        query = query.filter(VulnerabilityFinding.score_base >= f.score_min)
    if f.score_max is not None:
        query = query.filter(VulnerabilityFinding.score_base <= f.score_max)
    if f.groups or f.group_ids:
        member = (
            select(AssetGroupMember.asset_id)
            .join(AgentGroup, AgentGroup.id == AssetGroupMember.group_id)
            .where(AssetGroupMember.asset_id == Asset.id)
        )
        conditions = []
        if f.groups:
            conditions.append(AgentGroup.name.in_(f.groups))
        if f.group_ids:
            conditions.append(AgentGroup.id.in_(f.group_ids))
        query = query.filter(member.where(or_(*conditions)).exists())
    if f.search:
        like = f"%{f.search}%"
        query = query.filter(
            or_(
                VulnerabilityFinding.cve_id.ilike(like),
                Asset.hostname.ilike(like),
                Package.name.ilike(like),
                VulnerabilityCatalog.description.ilike(like),
            )
        )
    return query


def _groups_by_asset(db: Session, asset_ids: List[int]) -> dict:
    """Grupos de cada asset en UNA consulta (evita N+1 al serializar la página)."""
    if not asset_ids:
        return {}
    rows = (
        db.query(AssetGroupMember.asset_id, AgentGroup.name)
        .join(AgentGroup, AgentGroup.id == AssetGroupMember.group_id)
        .filter(AssetGroupMember.asset_id.in_(asset_ids))
        .all()
    )
    out = {}
    for asset_id, name in rows:
        out.setdefault(asset_id, []).append(name)
    for names in out.values():
        names.sort()
    return out


def _serialize_row(row, groups: dict) -> dict:
    finding, asset, package, catalog, connection, operating_system = row
    return {
        "id": finding.id,
        "connection_id": connection.id,
        "connection_name": connection.name,
        "status": finding.status,
        "asset_id": asset.id,
        "agent_id": asset.wazuh_agent_id,
        "agent_name": asset.hostname,
        "ip_address": asset.ip_address,
        "groups": groups.get(asset.id, []),
        "os_platform": operating_system.platform if operating_system else None,
        "os_version": operating_system.version if operating_system else None,
        "os_full": operating_system.full if operating_system else None,
        "package_id": package.id,
        "package_name": package.name,
        "package_version": package.version,
        "package_type": package.type,
        "package_arch": package.architecture,
        "cve_id": finding.cve_id,
        "severity": catalog.severity,
        "severity_rank": catalog.severity_rank,
        "score_base": float(finding.score_base) if finding.score_base is not None else None,
        "score_version": finding.score_version,
        "cvss_score": float(catalog.cvss_score) if catalog.cvss_score is not None else None,
        "description": catalog.description,
        "reference": catalog.reference,
        "scanner_vendor": finding.scanner_vendor,
        "detected_at": finding.detected_at,
        "published_at": catalog.published_at,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "resolved_at": finding.resolved_at,
    }


# ---------------------------------------------------------------------------
# Listado de vulnerabilidades
# ---------------------------------------------------------------------------
@app.get("/vulns")
def list_vulns(
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    group: Optional[str] = None,
    group_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    package_name: Optional[str] = None,
    severity: Optional[str] = None,
    rank_min: Optional[int] = None,
    os_platform: Optional[str] = None,
    os_version: Optional[str] = None,
    status: Optional[str] = None,
    score_min: Optional[float] = None,
    score_max: Optional[float] = None,
    search: Optional[str] = None,
    sort_by: str = "last_seen",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Listado paginado y filtrado 100% en la base de datos."""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    filters = VulnFilters(
        connection_id, agent_name, group, group_id, cve_id, package_name,
        severity, rank_min, os_platform, os_version, status, score_min,
        score_max, search,
    )
    query = _apply_vuln_filters(_finding_query(db), filters)
    total = query.order_by(None).count()

    sort_column = _SORTABLE_COLUMNS.get(sort_by, VulnerabilityFinding.last_seen)
    direction = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    query = query.order_by(direction, VulnerabilityFinding.id.asc())

    if limit is not None:
        query = query.limit(limit)
        page_size = limit
        page = 1
    else:
        query = query.offset((page - 1) * page_size).limit(page_size)

    rows = query.all()
    groups = _groups_by_asset(db, [row[1].id for row in rows])

    return {
        "items": [_serialize_row(row, groups) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if page_size else 1,
    }


@app.get("/vulns/filter-options")
def vuln_filter_options(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Opciones de filtro precalculadas en BD.

    En PostgreSQL cada lista sale de su procedimiento almacenado
    (``sp_filter_*``); en otros motores se usa el equivalente en ORM.
    """
    if _is_postgres(db):
        return _filter_options_pg(db, connection_id)
    return _filter_options_orm(db, connection_id)


def _sp(db: Session, name: str, **params):
    """Invoca un procedimiento almacenado con notación nombrada de PostgreSQL.

    ``p_x => :p_x`` deja el orden de los argumentos fuera de la ecuación y hace
    imposible pasar un valor a la posición equivocada al agregar parámetros.
    """
    args = ", ".join(f"{key} => :{key}" for key in params)
    return db.execute(text(f"SELECT * FROM {name}({args})"), params).mappings().all()


def _filter_options_pg(db: Session, connection_id: Optional[int]) -> dict:
    agents = _sp(db, "sp_filter_agents", p_connection_id=connection_id)
    groups = _sp(db, "sp_filter_groups", p_connection_id=connection_id)
    oses = _sp(db, "sp_filter_operating_systems", p_connection_id=connection_id)
    severities = _sp(db, "sp_filter_severities", p_connection_id=connection_id)
    packages = _sp(
        db, "sp_filter_packages", p_connection_id=connection_id, p_search=None,
        p_limit=2000,
    )
    cves = _sp(
        db, "sp_filter_cves", p_connection_id=connection_id, p_search=None, p_limit=5000
    )

    return {
        "agents": [r["hostname"] for r in agents if r["hostname"]],
        "groups": [
            {"id": r["group_id"], "name": r["name"], "assets": r["assets"],
             "activas": r["activas"]}
            for r in groups
        ],
        "operating_systems": [
            {"id": r["os_id"], "platform": r["platform"], "version": r["version"],
             "full": r["full_name"], "assets": r["assets"]}
            for r in oses
        ],
        "severities": [r["severity"] for r in severities],
        "severity_levels": [
            {"severity": r["severity"], "rank": r["severity_rank"], "total": r["total"],
             "score_min": float(r["score_min"]) if r["score_min"] is not None else None,
             "score_max": float(r["score_max"]) if r["score_max"] is not None else None}
            for r in severities
        ],
        "packages": [r["name"] for r in packages],
        "cves": [r["cve_id"] for r in cves],
    }


def _filter_options_orm(db: Session, connection_id: Optional[int]) -> dict:
    def scoped(query, join_asset=True):
        if connection_id and join_asset:
            query = query.filter(Asset.connection_id == connection_id)
        return query

    agents = scoped(
        db.query(Asset.hostname).filter(Asset.hostname.isnot(None)).distinct()
    ).all()
    groups = db.query(AgentGroup).filter(
        AgentGroup.connection_id == connection_id
    ).all() if connection_id else db.query(AgentGroup).all()
    oses = (
        db.query(OperatingSystem)
        .join(Asset, Asset.os_id == OperatingSystem.id)
        .distinct()
    )
    if connection_id:
        oses = oses.filter(Asset.connection_id == connection_id)

    sev_rows = scoped(
        db.query(VulnerabilityCatalog.severity, VulnerabilityCatalog.severity_rank)
        .join(VulnerabilityFinding, VulnerabilityFinding.cve_id == VulnerabilityCatalog.cve_id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .distinct()
    ).all()
    packages = scoped(
        db.query(Package.name)
        .join(VulnerabilityFinding, VulnerabilityFinding.package_id == Package.id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .distinct()
    ).all()
    cves = scoped(
        db.query(VulnerabilityFinding.cve_id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .distinct()
    ).all()

    return {
        "agents": sorted({row[0] for row in agents if row[0]}),
        "groups": [
            {"id": g.id, "name": g.name, "assets": None, "activas": None} for g in groups
        ],
        "operating_systems": [
            {"id": o.id, "platform": o.platform, "version": o.version, "full": o.full,
             "assets": None}
            for o in oses.all()
        ],
        "severities": sorted({row[0] for row in sev_rows}, key=lambda s: -SEVERITY_RANKS.get(s, 0)),
        "severity_levels": [
            {"severity": s, "rank": r, "total": None, "score_min": None, "score_max": None}
            for s, r in sorted(set(sev_rows), key=lambda item: -item[1])
        ],
        "packages": sorted({row[0] for row in packages if row[0]}),
        "cves": sorted({row[0] for row in cves if row[0]}),
    }


@app.get("/vulns/packages")
def package_inventory(
    connection_id: Optional[int] = None,
    search: Optional[str] = None,
    rank_min: int = 0,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Tabla de paquetes afectados (inventario de software vulnerable)."""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    if _is_postgres(db):
        rows = _sp(
            db, "sp_package_inventory",
            p_connection_id=connection_id, p_search=search, p_min_rank=rank_min,
            p_limit=page_size, p_offset=offset,
        )
        items = [
            {
                "package_id": r["package_id"], "name": r["name"], "version": r["version"],
                "type": r["type"], "architecture": r["architecture"],
                "afectados": r["afectados"], "activas": r["activas"],
                "resueltas": r["resueltas"],
                "max_score": float(r["max_score"]) if r["max_score"] is not None else None,
                "peor_severidad": r["peor_severidad"], "peor_rank": r["peor_rank"],
            }
            for r in rows
        ]
    else:
        items = _package_inventory_orm(db, connection_id, search, rank_min, page_size, offset)

    total_query = (
        db.query(sql_func.count(sql_func.distinct(Package.id)))
        .join(VulnerabilityFinding, VulnerabilityFinding.package_id == Package.id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityCatalog.severity_rank >= rank_min)
    )
    if connection_id:
        total_query = total_query.filter(Asset.connection_id == connection_id)
    if search:
        total_query = total_query.filter(Package.name.ilike(f"%{search}%"))
    total = total_query.scalar() or 0

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if page_size else 1,
    }


def _package_inventory_orm(db, connection_id, search, rank_min, limit, offset):
    query = (
        db.query(
            Package.id, Package.name, Package.version, Package.type, Package.architecture,
            sql_func.count(sql_func.distinct(VulnerabilityFinding.asset_id)),
            sql_func.sum(case((VulnerabilityFinding.status == "ACTIVE", 1), else_=0)),
            sql_func.sum(case((VulnerabilityFinding.status == "RESOLVED", 1), else_=0)),
            sql_func.max(VulnerabilityCatalog.cvss_score),
            sql_func.max(VulnerabilityCatalog.severity_rank),
        )
        .join(VulnerabilityFinding, VulnerabilityFinding.package_id == Package.id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityCatalog.severity_rank >= rank_min)
    )
    if connection_id:
        query = query.filter(Asset.connection_id == connection_id)
    if search:
        query = query.filter(Package.name.ilike(f"%{search}%"))

    query = (
        query.group_by(
            Package.id, Package.name, Package.version, Package.type, Package.architecture
        )
        .order_by(sql_func.max(VulnerabilityCatalog.severity_rank).desc(), Package.name)
        .offset(offset)
        .limit(limit)
    )

    rank_names = {v: k for k, v in SEVERITY_RANKS.items()}
    return [
        {
            "package_id": pid, "name": name, "version": version, "type": ptype,
            "architecture": arch, "afectados": afectados, "activas": activas or 0,
            "resueltas": resueltas or 0,
            "max_score": float(max_score) if max_score is not None else None,
            "peor_severidad": rank_names.get(max_rank, "Unknown"), "peor_rank": max_rank,
        }
        for (pid, name, version, ptype, arch, afectados, activas, resueltas,
             max_score, max_rank) in query.all()
    ]


@app.get("/vulns/{vuln_id}/history")
def vuln_history(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = _finding_query(db).filter(VulnerabilityFinding.id == vuln_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=VULN_NOT_FOUND)

    data = _serialize_row(row, _groups_by_asset(db, [row[1].id]))
    history = (
        db.query(FindingHistory)
        .filter(FindingHistory.finding_id == vuln_id)
        .order_by(FindingHistory.timestamp.asc())
        .all()
    )
    data["history"] = [
        {"id": h.id, "action": h.action, "details": h.details, "timestamp": h.timestamp}
        for h in history
    ]
    return data


# ---------------------------------------------------------------------------
# Periodos: la unidad de trabajo es el MES
# ---------------------------------------------------------------------------
_PERIOD_CONFIG = {
    "1m": {"months": 1, "unit": "day"},
    "3m": {"months": 3, "unit": "week"},
    "6m": {"months": 6, "unit": "month"},
    "12m": {"months": 12, "unit": "month"},
    "24m": {"months": 24, "unit": "month"},
    "all": {"months": 120, "unit": "month"},
}
DEFAULT_PERIOD = "12m"

# Compatibilidad con clientes antiguos que aún envían periodos en días.
_LEGACY_PERIODS = {"24h": "1m", "7d": "1m", "30d": "1m", "90d": "3m"}


def _resolve_period(period: Optional[str]) -> tuple:
    key = _LEGACY_PERIODS.get(period, period) or DEFAULT_PERIOD
    if key not in _PERIOD_CONFIG:
        key = DEFAULT_PERIOD
    return key, _PERIOD_CONFIG[key]


def _months_ago(value: datetime, months: int) -> datetime:
    total = value.year * 12 + (value.month - 1) - months
    year, month = divmod(total, 12)
    month += 1
    day = min(value.day, [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0)
                          else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
    return value.replace(year=year, month=month, day=day)


def _ensure_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _bucket_start(value: datetime, unit: str) -> datetime:
    value = _ensure_utc(value)
    if unit == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    midnight = value.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "day":
        return midnight
    if unit == "week":
        return midnight - timedelta(days=midnight.weekday())
    if unit == "year":
        return midnight.replace(month=1, day=1)
    return midnight.replace(day=1)  # month


# ---------------------------------------------------------------------------
# Evolución y trazabilidad
# ---------------------------------------------------------------------------
@app.get("/vulns/evolution/summary")
def vulnerability_evolution_summary(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    findings = db.query(VulnerabilityFinding).join(
        Asset, Asset.id == VulnerabilityFinding.asset_id
    )
    assets = db.query(Asset)
    detections = db.query(VulnerabilityDetection).join(
        VulnerabilityFinding, VulnerabilityFinding.id == VulnerabilityDetection.finding_id
    ).join(Asset, Asset.id == VulnerabilityFinding.asset_id)
    sync_query = db.query(sql_func.max(WazuhConnection.last_sync_at))

    if connection_id is not None:
        findings = findings.filter(Asset.connection_id == connection_id)
        assets = assets.filter(Asset.connection_id == connection_id)
        detections = detections.filter(Asset.connection_id == connection_id)
        sync_query = sync_query.filter(WazuhConnection.id == connection_id)

    last_sync_at = sync_query.scalar()
    return {
        "active_vulnerabilities": findings.filter(
            VulnerabilityFinding.status == "ACTIVE"
        ).count(),
        "resolved_vulnerabilities": findings.filter(
            VulnerabilityFinding.status == "RESOLVED"
        ).count(),
        "assets": assets.count(),
        "groups": (
            db.query(AgentGroup).filter(AgentGroup.connection_id == connection_id).count()
            if connection_id is not None else db.query(AgentGroup).count()
        ),
        "packages": db.query(sql_func.count(sql_func.distinct(Package.id))).scalar() or 0,
        "detection_events": detections.count(),
        "last_sync_at": last_sync_at.isoformat() if last_sync_at else None,
    }


@app.get("/vulns/evolution/monthly")
def monthly_vulnerability_trend(
    period: str = DEFAULT_PERIOD,
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Tendencia de detecciones agrupada por MES (antes era semanal)."""
    data = traceability_timeline(period, connection_id, None, None, db, current_user)
    return [
        {
            "mes": point["bucket"],
            "total_vulnerabilidades": point["nuevas"] + point["reemergidas"],
            "nuevas": point["nuevas"],
            "reemergidas": point["reemergidas"],
            "remediadas": point["remediadas"],
        }
        for point in data["points"]
    ]


@app.get("/vulns/evolution/timeline")
def traceability_timeline(
    period: str = DEFAULT_PERIOD,
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Nuevas vs. reemergidas vs. remediadas por bucket (meses por defecto)."""
    period_key, config = _resolve_period(period)
    end = datetime.now(timezone.utc)
    start = _months_ago(end, config["months"])
    agents = _split_csv(agent_name)
    cves = _split_csv(cve_id)

    if _is_postgres(db) and not agents and not cves:
        rows = _sp(
            db, "sp_traceability_timeline",
            p_connection_id=connection_id,
            p_unit=config["unit"],
            p_start=start,
            p_end=end,
        )
        points = [
            {
                "bucket": r["bucket"].isoformat() if r["bucket"] else None,
                "nuevas": r["nuevas"],
                "reemergidas": r["reemergidas"],
                "remediadas": r["remediadas"],
            }
            for r in rows
        ]
    else:
        points = _timeline_orm(db, connection_id, agents, cves, start, end, config["unit"])

    return {
        "period": period_key,
        "bucket": config["unit"],
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        "points": points,
    }


def _timeline_orm(db, connection_id, agents, cves, start, end, unit):
    query = (
        db.query(VulnerabilityDetection.timestamp, VulnerabilityDetection.status)
        .join(VulnerabilityFinding, VulnerabilityFinding.id == VulnerabilityDetection.finding_id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .filter(VulnerabilityDetection.timestamp >= start)
        .filter(VulnerabilityDetection.timestamp <= end)
    )
    if connection_id:
        query = query.filter(Asset.connection_id == connection_id)
    if agents:
        query = query.filter(Asset.hostname.in_(agents))
    if cves:
        query = query.filter(VulnerabilityFinding.cve_id.in_(cves))

    buckets = {}
    for timestamp, status in query.all():
        key = _bucket_start(timestamp, unit).isoformat()
        slot = buckets.setdefault(key, {"nuevas": 0, "reemergidas": 0, "remediadas": 0})
        if status == "Detected":
            slot["nuevas"] += 1
        elif status == "Re-emerged":
            slot["reemergidas"] += 1
        elif status == "Resolved":
            slot["remediadas"] += 1

    return [{"bucket": key, **counts} for key, counts in sorted(buckets.items())]


@app.get("/vulns/evolution/timeline-details")
def traceability_timeline_details(
    bucket_start: datetime,
    bucket_end: datetime,
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Drill-down: eventos de detección dentro de un bucket concreto."""
    limit = max(1, min(limit, 2000))

    query = (
        db.query(
            VulnerabilityDetection.timestamp,
            VulnerabilityDetection.status,
            VulnerabilityFinding.id,
            VulnerabilityFinding.cve_id,
            VulnerabilityFinding.status,
            Asset.hostname,
            WazuhConnection.name,
            Package.name,
            Package.version,
            VulnerabilityCatalog.severity,
        )
        .join(VulnerabilityFinding, VulnerabilityFinding.id == VulnerabilityDetection.finding_id)
        .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
        .join(WazuhConnection, WazuhConnection.id == Asset.connection_id)
        .join(Package, Package.id == VulnerabilityFinding.package_id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityDetection.timestamp >= bucket_start)
        .filter(VulnerabilityDetection.timestamp <= bucket_end)
    )
    if connection_id:
        query = query.filter(Asset.connection_id == connection_id)
    agents = _split_csv(agent_name)
    if agents:
        query = query.filter(Asset.hostname.in_(agents))
    cves = _split_csv(cve_id)
    if cves:
        query = query.filter(VulnerabilityFinding.cve_id.in_(cves))

    label_map = {"Detected": "DETECTED", "Re-emerged": "REOPENED", "Resolved": "RESOLVED"}
    rows = query.order_by(VulnerabilityDetection.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": finding_id,
            "connection_name": connection_name,
            "agent_name": hostname,
            "cve_id": cve,
            "severity": severity,
            "package_name": pkg_name,
            "package_version": pkg_version,
            "timeline_event_at": timestamp,
            "timeline_event_label": label_map.get(event_status, event_status),
            "status": finding_status,
        }
        for (timestamp, event_status, finding_id, cve, finding_status, hostname,
             connection_name, pkg_name, pkg_version, severity) in rows
    ]


@app.get("/vulns/evolution/traceability-summary")
def traceability_summary(
    connection_id: Optional[int] = None,
    new_window_months: int = 1,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Resumen del algoritmo de trazabilidad: Nuevas / Persistentes / Remediadas."""
    if _is_postgres(db):
        rows = db.execute(
            text("""
                SELECT nuevas, persistentes, remediadas, total_activas
                FROM sp_traceability_summary(
                    p_connection_id => :connection_id,
                    p_new_window    => CAST(:window AS INTERVAL)
                )
            """),
            {"connection_id": connection_id, "window": f"{new_window_months} months"},
        ).mappings().all()
        row = rows[0] if rows else None
        return {
            "nuevas": row["nuevas"] if row else 0,
            "persistentes": row["persistentes"] if row else 0,
            "remediadas": row["remediadas"] if row else 0,
            "total_activas": row["total_activas"] if row else 0,
            "ventana_meses": new_window_months,
        }

    cutoff = _months_ago(datetime.now(timezone.utc), new_window_months)
    base = db.query(VulnerabilityFinding).join(Asset, Asset.id == VulnerabilityFinding.asset_id)
    if connection_id:
        base = base.filter(Asset.connection_id == connection_id)

    active = base.filter(VulnerabilityFinding.status == "ACTIVE")
    nuevas = active.filter(VulnerabilityFinding.first_seen >= cutoff).count()
    total_activas = active.count()
    return {
        "nuevas": nuevas,
        "persistentes": total_activas - nuevas,
        "remediadas": base.filter(VulnerabilityFinding.status == "RESOLVED").count(),
        "total_activas": total_activas,
        "ventana_meses": new_window_months,
    }


@app.get("/vulns/evolution/top-assets")
def top_vulnerable_assets(
    limit: int = 5,
    connection_id: Optional[int] = None,
    rank_min: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Servidores con más CVEs activos distintos."""
    limit = max(1, min(limit, 50))
    query = (
        db.query(
            Asset.hostname,
            sql_func.count(sql_func.distinct(VulnerabilityFinding.cve_id)).label("total"),
        )
        .join(VulnerabilityFinding, VulnerabilityFinding.asset_id == Asset.id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityFinding.status == "ACTIVE")
        .filter(VulnerabilityCatalog.severity_rank >= rank_min)
    )
    if connection_id is not None:
        query = query.filter(Asset.connection_id == connection_id)

    rows = (
        query.group_by(Asset.hostname)
        .order_by(sql_func.count(sql_func.distinct(VulnerabilityFinding.cve_id)).desc())
        .limit(limit)
        .all()
    )
    return [
        {"hostname": hostname or "Sin hostname", "total": total} for hostname, total in rows
    ]


# ---------------------------------------------------------------------------
# Línea de tiempo tipo Gantt
# ---------------------------------------------------------------------------
def _coverage_since(db: Session, connection_id: Optional[int]):
    """Primer instante con datos: antes de esa fecha no sabemos nada.

    Sirve para que el frontend deje en blanco SOLO el periodo en que consta
    que la vulnerabilidad no existía (hubo sincronización y no la reportó).
    """
    query = db.query(sql_func.min(VulnerabilityDetection.timestamp)).join(
        VulnerabilityFinding, VulnerabilityFinding.id == VulnerabilityDetection.finding_id
    ).join(Asset, Asset.id == VulnerabilityFinding.asset_id)
    if connection_id is not None:
        query = query.filter(Asset.connection_id == connection_id)
    return query.scalar()


@app.get("/vulns/evolution/threats")
def threat_spans(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    group: Optional[str] = None,
    group_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    package_name: Optional[str] = None,
    severity: Optional[str] = None,
    rank_min: Optional[int] = None,
    os_platform: Optional[str] = None,
    os_version: Optional[str] = None,
    status: Optional[str] = None,
    score_min: Optional[float] = None,
    score_max: Optional[float] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Una barra por amenaza única, con su ciclo de vida detección → resolución.

    Cada elemento trae ``start`` (first_seen), ``resolved_at`` y ``end`` para que
    el frontend pinte: blanco antes de existir, color por severidad mientras
    está activa y verde desde que se resolvió.
    """
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    now = datetime.now(timezone.utc)
    end = _ensure_utc(end) if end else now
    start = _ensure_utc(start) if start else _months_ago(end, 1)

    filters = VulnFilters(
        connection_id, agent_name, group, group_id, cve_id, package_name,
        severity, rank_min, os_platform, os_version, status, score_min, score_max, None,
    )
    base = _apply_vuln_filters(_finding_query(db), filters)

    # Una amenaza aparece en el rango si nació antes del fin y sigue activa o
    # tuvo actividad dentro del rango.
    in_range = base.filter(VulnerabilityFinding.first_seen <= end).filter(
        or_(
            VulnerabilityFinding.status == "ACTIVE",
            VulnerabilityFinding.last_seen >= start,
        )
    )

    total = in_range.order_by(None).count()
    active = in_range.filter(VulnerabilityFinding.status == "ACTIVE").order_by(None).count()

    rows = (
        in_range.order_by(
            VulnerabilityCatalog.severity_rank.desc(),
            VulnerabilityFinding.first_seen.asc(),
            VulnerabilityFinding.id.asc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    groups = _groups_by_asset(db, [row[1].id for row in rows])
    since = _coverage_since(db, connection_id)

    items = []
    for finding, asset, package, catalog, connection, _os in rows:
        resolved_at = finding.resolved_at or (
            finding.last_seen if finding.status == "RESOLVED" else None
        )
        items.append({
            "id": finding.id,
            "cve_id": finding.cve_id,
            "connection_id": connection.id,
            "connection_name": connection.name,
            "agent_name": asset.hostname,
            "groups": groups.get(asset.id, []),
            "package_name": package.name,
            "package_version": package.version,
            "severity": catalog.severity,
            "severity_rank": catalog.severity_rank,
            "score_base": float(finding.score_base) if finding.score_base is not None else None,
            "status": finding.status,
            "start": finding.first_seen.isoformat() if finding.first_seen else None,
            "resolved_at": resolved_at.isoformat() if resolved_at else None,
            "end": resolved_at.isoformat() if finding.status == "RESOLVED" and resolved_at else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
        })

    return {
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        # Desde cuándo hay datos: antes de esto el estado es DESCONOCIDO.
        "coverage": {"since": since.isoformat() if since else None},
        "total": total,
        "active": active,
        "resolved": total - active,
        "returned": len(items),
        "limit": limit,
        "offset": offset,
        "items": items,
    }


# ---------------------------------------------------------------------------
# Dashboard: gráficos de torta e histograma
# ---------------------------------------------------------------------------
@app.get("/vulns/dashboard/status-breakdown")
def dashboard_status_breakdown(
    connection_id: Optional[int] = None,
    group_id: Optional[int] = None,
    rank_min: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Torta resueltas vs. activas."""
    if _is_postgres(db):
        row = _sp(
            db, "sp_status_breakdown",
            p_connection_id=connection_id, p_group_id=group_id, p_min_rank=rank_min,
        )
        activas = row[0]["activas"] if row else 0
        resueltas = row[0]["resueltas"] if row else 0
    else:
        query = (
            db.query(VulnerabilityFinding.status, sql_func.count())
            .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
            .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
            .filter(VulnerabilityCatalog.severity_rank >= rank_min)
        )
        if connection_id:
            query = query.filter(Asset.connection_id == connection_id)
        if group_id:
            query = query.filter(
                select(AssetGroupMember.asset_id)
                .where(AssetGroupMember.asset_id == Asset.id)
                .where(AssetGroupMember.group_id == group_id)
                .exists()
            )
        counts = dict(query.group_by(VulnerabilityFinding.status).all())
        activas = counts.get("ACTIVE", 0)
        resueltas = counts.get("RESOLVED", 0)

    total = activas + resueltas
    return {
        "activas": activas,
        "resueltas": resueltas,
        "total": total,
        "pct_activas": round(100.0 * activas / total, 1) if total else 0.0,
        "pct_resueltas": round(100.0 * resueltas / total, 1) if total else 0.0,
    }


@app.get("/vulns/dashboard/new-unresolved")
def dashboard_new_unresolved(
    year: Optional[int] = None,
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """% de vulnerabilidades detectadas en el año que siguen sin corregir."""
    year = year or datetime.now(timezone.utc).year

    if _is_postgres(db):
        row = _sp(db, "sp_new_unresolved_ratio", p_connection_id=connection_id, p_year=year)
        data = row[0] if row else {}
        nuevas = data.get("nuevas", 0) or 0
        sin_corregir = data.get("sin_corregir", 0) or 0
        corregidas = data.get("corregidas", 0) or 0
    else:
        start = datetime(year, 1, 1, tzinfo=timezone.utc)
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        query = (
            db.query(VulnerabilityFinding.status, sql_func.count())
            .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
            .filter(VulnerabilityFinding.first_seen >= start)
            .filter(VulnerabilityFinding.first_seen < end)
        )
        if connection_id:
            query = query.filter(Asset.connection_id == connection_id)
        counts = dict(query.group_by(VulnerabilityFinding.status).all())
        sin_corregir = counts.get("ACTIVE", 0)
        corregidas = counts.get("RESOLVED", 0)
        nuevas = sin_corregir + corregidas

    return {
        "anio": year,
        "nuevas": nuevas,
        "sin_corregir": sin_corregir,
        "corregidas": corregidas,
        "pct_sin_corregir": round(100.0 * sin_corregir / nuevas, 1) if nuevas else 0.0,
    }


@app.get("/vulns/dashboard/critical-coverage")
def dashboard_critical_coverage(
    connection_id: Optional[int] = None,
    rank_min: int = 4,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """% de servidores y de grupos con al menos una vulnerabilidad crítica."""
    if _is_postgres(db):
        row = _sp(db, "sp_critical_coverage", p_connection_id=connection_id, p_min_rank=rank_min)
        data = dict(row[0]) if row else {}
        return {
            "rank_min": rank_min,
            "total_agentes": data.get("total_agentes", 0) or 0,
            "agentes_criticos": data.get("agentes_criticos", 0) or 0,
            "pct_agentes": float(data.get("pct_agentes") or 0.0),
            "total_grupos": data.get("total_grupos", 0) or 0,
            "grupos_criticos": data.get("grupos_criticos", 0) or 0,
            "pct_grupos": float(data.get("pct_grupos") or 0.0),
        }

    assets = db.query(Asset)
    groups = db.query(AgentGroup)
    if connection_id:
        assets = assets.filter(Asset.connection_id == connection_id)
        groups = groups.filter(AgentGroup.connection_id == connection_id)

    critical_assets = {
        row[0]
        for row in db.query(VulnerabilityFinding.asset_id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityFinding.status == "ACTIVE")
        .filter(VulnerabilityCatalog.severity_rank >= rank_min)
        .distinct()
        .all()
    }
    asset_ids = [a.id for a in assets.all()]
    group_rows = groups.all()
    critical_groups = {
        row[0]
        for row in db.query(AssetGroupMember.group_id)
        .filter(AssetGroupMember.asset_id.in_(critical_assets or [0]))
        .distinct()
        .all()
    }

    total_agentes = len(asset_ids)
    agentes_criticos = len([a for a in asset_ids if a in critical_assets])
    total_grupos = len(group_rows)
    grupos_criticos = len([g for g in group_rows if g.id in critical_groups])
    return {
        "rank_min": rank_min,
        "total_agentes": total_agentes,
        "agentes_criticos": agentes_criticos,
        "pct_agentes": round(100.0 * agentes_criticos / total_agentes, 1) if total_agentes else 0.0,
        "total_grupos": total_grupos,
        "grupos_criticos": grupos_criticos,
        "pct_grupos": round(100.0 * grupos_criticos / total_grupos, 1) if total_grupos else 0.0,
    }


@app.get("/vulns/dashboard/critical-histogram")
def dashboard_critical_histogram(
    connection_id: Optional[int] = None,
    rank_min: int = 4,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Histograma: agentes con al menos una vulnerabilidad crítica."""
    limit = max(1, min(limit, 200))

    if _is_postgres(db):
        rows = _sp(
            db, "sp_critical_histogram",
            p_connection_id=connection_id, p_min_rank=rank_min, p_limit=limit,
        )
        return [
            {
                "asset_id": r["asset_id"], "hostname": r["hostname"], "grupos": r["grupos"],
                "criticas": r["criticas"], "activas": r["activas"],
                "max_score": float(r["max_score"]) if r["max_score"] is not None else None,
            }
            for r in rows
        ]

    criticas = sql_func.sum(
        case((VulnerabilityCatalog.severity_rank >= rank_min, 1), else_=0)
    )
    query = (
        db.query(
            Asset.id, Asset.hostname, Asset.wazuh_agent_id,
            criticas.label("criticas"),
            sql_func.count().label("activas"),
            sql_func.max(VulnerabilityCatalog.cvss_score),
        )
        .join(VulnerabilityFinding, VulnerabilityFinding.asset_id == Asset.id)
        .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
        .filter(VulnerabilityFinding.status == "ACTIVE")
        .group_by(Asset.id, Asset.hostname, Asset.wazuh_agent_id)
        .having(criticas > 0)
        .order_by(criticas.desc())
        .limit(limit)
    )
    if connection_id:
        query = query.filter(Asset.connection_id == connection_id)

    rows = query.all()
    group_map = _groups_by_asset(db, [row[0] for row in rows])
    return [
        {
            "asset_id": asset_id,
            "hostname": hostname or agent_id,
            "grupos": ", ".join(group_map.get(asset_id, [])),
            "criticas": int(crit or 0),
            "activas": activas,
            "max_score": float(max_score) if max_score is not None else None,
        }
        for asset_id, hostname, agent_id, crit, activas, max_score in rows
    ]


@app.get("/vulns/dashboard/group-risk")
def dashboard_group_risk(
    connection_id: Optional[int] = None,
    rank_min: int = 4,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Riesgo agregado por grupo de agentes."""
    limit = max(1, min(limit, 200))

    if _is_postgres(db):
        rows = _sp(
            db, "sp_group_risk",
            p_connection_id=connection_id, p_min_rank=rank_min, p_limit=limit,
        )
        return [
            {
                "group_id": r["group_id"], "name": r["name"], "agentes": r["agentes"],
                "agentes_criticos": r["agentes_criticos"], "criticas": r["criticas"],
                "activas": r["activas"],
            }
            for r in rows
        ]

    out = []
    groups = db.query(AgentGroup)
    if connection_id:
        groups = groups.filter(AgentGroup.connection_id == connection_id)

    for group in groups.limit(limit).all():
        asset_ids = [
            row[0]
            for row in db.query(AssetGroupMember.asset_id)
            .filter(AssetGroupMember.group_id == group.id)
            .all()
        ]
        if not asset_ids:
            out.append({
                "group_id": group.id, "name": group.name, "agentes": 0,
                "agentes_criticos": 0, "criticas": 0, "activas": 0,
            })
            continue

        rows = (
            db.query(VulnerabilityFinding.asset_id, VulnerabilityCatalog.severity_rank)
            .join(VulnerabilityCatalog, VulnerabilityCatalog.cve_id == VulnerabilityFinding.cve_id)
            .filter(VulnerabilityFinding.asset_id.in_(asset_ids))
            .filter(VulnerabilityFinding.status == "ACTIVE")
            .all()
        )
        criticas = [row for row in rows if row[1] >= rank_min]
        out.append({
            "group_id": group.id,
            "name": group.name,
            "agentes": len(asset_ids),
            "agentes_criticos": len({row[0] for row in criticas}),
            "criticas": len(criticas),
            "activas": len(rows),
        })

    out.sort(key=lambda item: (item["criticas"], item["activas"]), reverse=True)
    return out
