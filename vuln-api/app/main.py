# app/main.py
import re
import os
import math
import uuid
import threading
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import set_key, find_dotenv
from sqlalchemy.orm import Session, selectinload
from typing import List, Annotated, Optional
from pydantic import BaseModel
from sqlalchemy import text, func as sql_func, case, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func
from .db import Base, engine, get_db, SessionLocal
from .models import (
    Asset,
    Manager,
    User,
    VulnerabilityCatalog,
    VulnerabilityDetection,
    WazuhVulnerability,
    WazuhConnection,
)
from .auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from .models import User, WazuhVulnerability, WazuhConnection, VulnerabilityHistory
from .wazuh_client import fetch_all_vulns, test_connection
from .crypto import encrypt, decrypt

Base.metadata.create_all(bind=engine)


def initialize_timescale_storage():
    if engine.dialect.name != "postgresql":
        return

    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            conn.execute(text("""
                SELECT create_hypertable(
                    'vulnerability_detections',
                    'timestamp',
                    if_not_exists => TRUE,
                    migrate_data => TRUE
                )
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_vuln_detections_asset_time
                ON vulnerability_detections (asset_id, timestamp DESC)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_vuln_detections_cve_time
                ON vulnerability_detections (cve_id, timestamp DESC)
            """))
    except SQLAlchemyError as exc:
        print(f"TimescaleDB no disponible, se usara PostgreSQL estandar: {exc}")


def initialize_analytics_objects():
    """Crea índices y procedimientos almacenados para acelerar filtros y trazabilidad.

    Toda la agregación pesada vive en la base de datos (Processing component):
    el frontend solo consume resultados precalculados con baja latencia.
    """
    if engine.dialect.name != "postgresql":
        return

    try:
        with engine.begin() as conn:
            # --- Índices para filtros server-side sobre wazuh_vulnerabilities ---
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_conn_status
                ON wazuh_vulnerabilities (connection_id, status)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_agent_name
                ON wazuh_vulnerabilities (agent_name)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_cve ON wazuh_vulnerabilities (cve_id)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_severity
                ON wazuh_vulnerabilities (severity)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_last_seen
                ON wazuh_vulnerabilities (last_seen DESC)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_wv_package_name
                ON wazuh_vulnerabilities (package_name)
            """))

            # --- Procedimiento almacenado: línea de trazabilidad por bucket de tiempo ---
            # Devuelve, por cada bucket, cuántas vulnerabilidades fueron Nuevas,
            # Reemergidas y Remediadas (estados del algoritmo de trazabilidad).
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION sp_traceability_timeline(
                    p_connection_id INTEGER,
                    p_bucket INTERVAL,
                    p_start TIMESTAMPTZ,
                    p_end TIMESTAMPTZ
                )
                RETURNS TABLE(
                    bucket TIMESTAMPTZ,
                    nuevas BIGINT,
                    reemergidas BIGINT,
                    remediadas BIGINT
                )
                LANGUAGE sql STABLE AS $$
                    SELECT
                        time_bucket(p_bucket, vd.timestamp) AS bucket,
                        count(*) FILTER (WHERE vd.status = 'Detected')    AS nuevas,
                        count(*) FILTER (WHERE vd.status = 'Re-emerged')  AS reemergidas,
                        count(*) FILTER (WHERE vd.status = 'Resolved')    AS remediadas
                    FROM vulnerability_detections vd
                    JOIN assets a   ON a.id = vd.asset_id
                    JOIN managers m ON m.id = a.manager_id
                    WHERE vd.timestamp >= p_start
                      AND vd.timestamp <= p_end
                      AND (p_connection_id IS NULL OR m.legacy_connection_id = p_connection_id)
                    GROUP BY bucket
                    ORDER BY bucket
                $$;
            """))

            # --- Procedimiento almacenado: resumen de trazabilidad (cards) ---
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION sp_traceability_summary(
                    p_connection_id INTEGER,
                    p_new_window INTERVAL DEFAULT INTERVAL '7 days'
                )
                RETURNS TABLE(
                    nuevas BIGINT,
                    persistentes BIGINT,
                    remediadas BIGINT,
                    total_activas BIGINT
                )
                LANGUAGE sql STABLE AS $$
                    SELECT
                        count(*) FILTER (
                            WHERE wv.status = 'ACTIVE'
                              AND wv.first_seen >= now() - p_new_window
                        ) AS nuevas,
                        count(*) FILTER (
                            WHERE wv.status = 'ACTIVE'
                              AND wv.first_seen < now() - p_new_window
                        ) AS persistentes,
                        count(*) FILTER (WHERE wv.status = 'RESOLVED') AS remediadas,
                        count(*) FILTER (WHERE wv.status = 'ACTIVE')   AS total_activas
                    FROM wazuh_vulnerabilities wv
                    WHERE (p_connection_id IS NULL OR wv.connection_id = p_connection_id)
                $$;
            """))
    except SQLAlchemyError as exc:
        print(f"No se pudieron crear objetos analíticos: {exc}")


initialize_timescale_storage()
initialize_analytics_objects()

CONNECTION_NOT_FOUND = "Conexión no encontrada"

# ---------------------------------------------------------------------------
# Registro de trabajos de sincronización en segundo plano (progreso + toast)
# ---------------------------------------------------------------------------
SYNC_JOBS: dict = {}
SYNC_JOBS_LOCK = threading.Lock()
MAX_SYNC_JOBS = 20

# En tests (o entornos sin worker) ejecuta la sincronización de forma
# síncrona en la misma sesión de la petición, en vez de lanzar un hilo.
SYNC_INLINE = os.getenv("SYNC_INLINE", "").strip().lower() in ("1", "true", "yes")


def _new_sync_job() -> str:
    job_id = str(uuid.uuid4())
    with SYNC_JOBS_LOCK:
        # Limita el historial de trabajos en memoria
        if len(SYNC_JOBS) >= MAX_SYNC_JOBS:
            oldest = sorted(SYNC_JOBS.items(), key=lambda kv: kv[1]["started_at"])
            for old_id, _ in oldest[: len(SYNC_JOBS) - MAX_SYNC_JOBS + 1]:
                SYNC_JOBS.pop(old_id, None)
        SYNC_JOBS[job_id] = {
            "job_id": job_id,
            "status": "pending",      # pending | running | completed | error
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


class WazuhConnectionResponse(BaseModel):
    id: int
    name: str
    indexer_url: str
    wazuh_user: str
    is_active: bool


def create_default_admin():
    db = SessionLocal()
    try:
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            print("Creando usuario admin default...")
            default_admin = User(
                username="admin", 
                password_hash=hash_password("admin"), 
                is_active=True,
                is_default_password=True,
            )
            db.add(default_admin)
            db.commit()
    finally:
        db.close()


create_default_admin()

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


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
            status_code=400,
            detail="La nueva contraseña debe ser diferente a la anterior",
        )

    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Las contraseñas nuevas no coinciden",
        )

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
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya esta ocupado. Elige otro.")

    new_user = User(
        username=request.username, 
        password_hash=hash_password(request.password),
        is_default_password=True,
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}


@app.get("/users")
def list_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username} for u in users]


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


@app.get("/wazuh-connections")
def list_connections(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    conns = db.query(WazuhConnection).all()
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
        for c in conns
    ]


@app.post("/wazuh-connections", status_code=201)
def create_connection(
    request: WazuhConnectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # verify unique name
    if db.query(WazuhConnection).filter(WazuhConnection.name == request.name).first():
        raise HTTPException(
            status_code=400, detail="Ya existe una conexión con ese nombre"
        )

    # try to connect before persisting
    ok = test_connection(request.indexer_url, request.wazuh_user, request.wazuh_password)
    if not ok:
        # do not store invalid configuration
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
        last_tested_at=func.now(),
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

    _delete_connection_data(db, conn_id)
    db.delete(conn)
    db.commit()
    return {"message": "Conexión eliminada"}


def _delete_connection_data(db: Session, conn_id: int) -> None:
    vuln_ids = [
        item.id
        for item in db.query(WazuhVulnerability.id)
        .filter(WazuhVulnerability.connection_id == conn_id)
        .all()
    ]

    if vuln_ids:
        db.query(VulnerabilityHistory).filter(
            VulnerabilityHistory.vulnerability_id.in_(vuln_ids)
        ).delete(synchronize_session=False)
        db.query(WazuhVulnerability).filter(
            WazuhVulnerability.id.in_(vuln_ids)
        ).delete(synchronize_session=False)

    managers = db.query(Manager).filter(
        Manager.legacy_connection_id == conn_id
    ).all()

    for manager in managers:
        asset_ids = [
            item.id
            for item in db.query(Asset.id)
            .filter(Asset.manager_id == manager.id)
            .all()
        ]

        if asset_ids:
            db.query(VulnerabilityDetection).filter(
                VulnerabilityDetection.asset_id.in_(asset_ids)
            ).delete(synchronize_session=False)
            db.query(Asset).filter(
                Asset.id.in_(asset_ids)
            ).delete(synchronize_session=False)

        db.delete(manager)


@app.post("/wazuh-connections/{conn_id}/test")
def test_wazuh_connection(
    conn_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    ok = test_connection(
        conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password)
    )

    conn.tested = True
    conn.last_tested_at = func.now()
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


def _parse_wazuh_timestamp(v: dict, fallback: datetime) -> datetime:
    """Usa el @timestamp del documento Wazuh si está disponible; si no, el fallback local."""
    raw = v.get("@timestamp")
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
    # Intento secundario: vulnerability.detected_at
    vuln = v.get("vulnerability") or {}
    raw2 = vuln.get("detected_at")
    if raw2:
        try:
            return datetime.fromisoformat(raw2.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
    return fallback


def _normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "Low"
    normalized = value.strip().lower()
    if normalized in {"critical", "critica", "crítica"}:
        return "Critical"
    if normalized in {"high", "alta"}:
        return "High"
    if normalized in {"medium", "media"}:
        return "Medium"
    return "Low"


def _score_base(vuln: dict):
    score = (vuln.get("score") or {}).get("base")
    if score in ("", None):
        return None
    return score


def _vault_ref_for_connection(conn_id: int) -> str:
    return f"wazuh_connection:{conn_id}:wazuh_password"


def _get_or_create_manager(db: Session, conn: WazuhConnection) -> Manager:
    manager = db.query(Manager).filter(Manager.legacy_connection_id == conn.id).first()
    if not manager:
        manager = db.query(Manager).filter(
            Manager.api_key_vault_ref == _vault_ref_for_connection(conn.id)
        ).first()

    if not manager:
        manager = Manager(
            nombre=conn.name,
            api_url=conn.indexer_url,
            api_key_vault_ref=_vault_ref_for_connection(conn.id),
            legacy_connection_id=conn.id,
        )
        db.add(manager)
        db.flush()
    else:
        manager.nombre = conn.name
        manager.api_url = conn.indexer_url
        manager.api_key_vault_ref = _vault_ref_for_connection(conn.id)
        manager.legacy_connection_id = conn.id

    return manager


def _extract_ip(agent: dict, raw_vuln: dict) -> Optional[str]:
    host = raw_vuln.get("host") or {}
    ip_value = agent.get("ip") or host.get("ip") or raw_vuln.get("ip")
    if isinstance(ip_value, list):
        return ip_value[0] if ip_value else None
    return ip_value


def _get_or_create_asset(
    db: Session,
    manager: Manager,
    agent: dict,
    osinfo: dict,
    raw_vuln: dict,
) -> Asset:
    wazuh_agent_id = agent.get("id") or "unknown"
    asset = db.query(Asset).filter(
        Asset.manager_id == manager.id,
        Asset.wazuh_agent_id == wazuh_agent_id,
    ).first()

    if not asset:
        asset = Asset(manager_id=manager.id, wazuh_agent_id=wazuh_agent_id)
        db.add(asset)
        db.flush()

    asset.hostname = agent.get("name") or asset.hostname
    asset.os_version = osinfo.get("full") or osinfo.get("version") or asset.os_version
    asset.ip_address = _extract_ip(agent, raw_vuln) or asset.ip_address
    return asset


def _upsert_catalog(db: Session, vuln: dict) -> VulnerabilityCatalog:
    cve_id = vuln.get("id")
    catalog = db.query(VulnerabilityCatalog).filter(
        VulnerabilityCatalog.cve_id == cve_id
    ).first()

    if not catalog:
        catalog = VulnerabilityCatalog(cve_id=cve_id)
        db.add(catalog)

    catalog.severity = _normalize_severity(vuln.get("severity"))
    catalog.description = vuln.get("description")
    catalog.cvss_score = _score_base(vuln)
    return catalog


def _record_detection_event(
    db: Session,
    asset_id: str,
    cve_id: str,
    status: str,
    pkg: dict,
    scan_timestamp: datetime,
) -> None:
    db.add(VulnerabilityDetection(
        timestamp=scan_timestamp,
        asset_id=asset_id,
        cve_id=cve_id,
        status=status,
        package_name=pkg.get("name") or "",
        package_version=pkg.get("version") or "",
    ))


def _handle_existing_vuln(db: Session, existing: WazuhVulnerability, vuln: dict) -> None:
    if existing.status == "RESOLVED":
        existing.status = "ACTIVE"
        db.add(VulnerabilityHistory(
            vulnerability_id=existing.id,
            action="REOPENED",
            details="La vulnerabilidad fue detectada nuevamente por Wazuh",
        ))

    if existing.severity != vuln.get("severity"):
        db.add(VulnerabilityHistory(
            vulnerability_id=existing.id,
            action="SEVERITY_CHANGED",
            details=f"Severidad cambió de {existing.severity} a {vuln.get('severity')}",
        ))
        existing.severity = vuln.get("severity")

    existing.score_base = (vuln.get("score") or {}).get("base")
    existing.last_seen = func.now()


def _event_status_for_existing(existing: WazuhVulnerability) -> str:
    if existing.status == "RESOLVED":
        return "Re-emerged"
    return "Detected"


def process_wazuh_vulnerabilities(
    db: Session, conn_id: int, raw_vulns: list, progress_cb=None
) -> int:
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    count = 0
    total = len(raw_vulns)
    seen_vuln_ids = set()
    scan_timestamp = datetime.now(timezone.utc)
    manager = _get_or_create_manager(db, conn)

    active_vulns_in_db = db.query(WazuhVulnerability).filter_by(connection_id=conn_id, status="ACTIVE").all()
    active_vuln_dict = {v.id: v for v in active_vulns_in_db}

    for idx, v in enumerate(raw_vulns):
        if progress_cb and (idx % 200 == 0):
            progress_cb(idx, total)
        agent = v.get("agent", {})
        osinfo = (v.get("host") or {}).get("os") or {}
        pkg = v.get("package", {})
        vuln = v.get("vulnerability", {})

        if not vuln.get("id"):
            continue

        asset = _get_or_create_asset(db, manager, agent, osinfo, v)
        catalog = _upsert_catalog(db, vuln)

        existing = db.query(WazuhVulnerability).filter_by(
            connection_id=conn_id,
            agent_id=agent.get("id"),
            package_name=pkg.get("name"),
            package_version=pkg.get("version"),
            cve_id=vuln.get("id"),
        ).first()

        if existing:
            event_status = _event_status_for_existing(existing)
            seen_vuln_ids.add(existing.id)
            _handle_existing_vuln(db, existing, vuln)
        else:
            event_status = "Detected"
            new_vuln = _create_new_vuln(db, conn_id, agent, osinfo, pkg, vuln)
            seen_vuln_ids.add(new_vuln.id)

        wazuh_ts = _parse_wazuh_timestamp(v, scan_timestamp)
        _record_detection_event(
            db,
            asset.id,
            catalog.cve_id,
            event_status,
            pkg,
            wazuh_ts,
        )
        count += 1

    _resolve_missing_vulns(db, manager, active_vuln_dict, seen_vuln_ids, scan_timestamp)

    if progress_cb:
        progress_cb(total, total)

    conn.last_sync_at = scan_timestamp
    return count


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
        job_id,
        status="running",
        phase="Iniciando",
        connections_total=len(conn_ids),
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
                    job_id,
                    phase=f"Procesando {conn.name}",
                    total=len(raw_vulns),
                )

                def _cb(done, total, _name=conn.name):
                    _update_sync_job(
                        job_id,
                        processed=done,
                        total=total,
                        phase=f"Procesando {_name} ({done}/{total})",
                    )

                count = process_wazuh_vulnerabilities(db, conn.id, raw_vulns, progress_cb=_cb)
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
        # Ejecución síncrona usando la sesión de la petición (tests).
        _run_sync_job(job_id, conn_ids, db=db)
        return job_id
    thread = threading.Thread(target=_run_sync_job, args=(job_id, conn_ids), daemon=True)
    thread.start()
    return job_id


def _create_new_vuln(db, conn_id, agent, osinfo, pkg, vuln):
    new_vuln = WazuhVulnerability(
        connection_id=conn_id,
        status="ACTIVE",
        agent_id=agent.get("id"),
        agent_name=agent.get("name"),
        os_full=osinfo.get("full"),
        os_platform=osinfo.get("platform"),
        os_version=osinfo.get("version"),
        package_name=pkg.get("name"),
        package_version=pkg.get("version"),
        package_type=pkg.get("type"),
        package_arch=pkg.get("architecture"),
        cve_id=vuln.get("id"),
        severity=vuln.get("severity"),
        score_base=(vuln.get("score") or {}).get("base"),
        score_version=(vuln.get("score") or {}).get("version"),
        detected_at=vuln.get("detected_at"),
        published_at=vuln.get("published_at"),
        description=vuln.get("description"),
        reference=vuln.get("reference"),
        scanner_vendor=(vuln.get("scanner") or {}).get("vendor"),
    )
    db.add(new_vuln)
    db.flush()
    db.add(VulnerabilityHistory(
        vulnerability_id=new_vuln.id,
        action="DETECTED",
        details="Vulnerabilidad identificada por primera vez",
    ))
    return new_vuln


def _resolve_missing_vulns(db, manager, active_vuln_dict, seen_vuln_ids, scan_timestamp):
    for vuln_id, db_vuln in active_vuln_dict.items():
        if vuln_id not in seen_vuln_ids:
            db_vuln.status = "RESOLVED"
            db.add(VulnerabilityHistory(
                vulnerability_id=vuln_id,
                action="RESOLVED",
                details="Ya no es reportada por el agente (Probablemente parcheada)",
            ))
            asset = _get_or_create_asset(
                db,
                manager,
                {"id": db_vuln.agent_id, "name": db_vuln.agent_name},
                {"full": db_vuln.os_full, "version": db_vuln.os_version},
                {},
            )
            catalog = _upsert_catalog(db, {
                "id": db_vuln.cve_id,
                "severity": db_vuln.severity,
                "description": db_vuln.description,
                "score": {"base": db_vuln.score_base},
            })
            _record_detection_event(
                db,
                asset.id,
                catalog.cve_id,
                "Resolved",
                {"name": db_vuln.package_name, "version": db_vuln.package_version},
                scan_timestamp,
            )


@app.post("/vulns/sync-all")
def sync_all_connections(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Lanza la sincronización en segundo plano y devuelve un job_id.

    El frontend consulta /sync/status?job_id=... para mostrar la barra de
    progreso y dispara un toast al completarse, sin bloquear la petición.
    """
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    if not conns:
        raise HTTPException(status_code=400, detail="No hay conexiones activas para sincronizar")

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
    job_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """Devuelve el progreso de un job de sincronización.

    Sin job_id devuelve el trabajo más reciente (para reanudar la barra de
    progreso si el usuario recarga la página mientras sincroniza).
    """
    with SYNC_JOBS_LOCK:
        if job_id:
            job = SYNC_JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job no encontrado")
            return dict(job)

        if not SYNC_JOBS:
            return {"status": "idle", "job_id": None}

        latest = max(SYNC_JOBS.values(), key=lambda j: j["started_at"])
        return dict(latest)


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


# Orden lógico de severidad para el ordenamiento server-side
_SEVERITY_RANK = case(
    (sql_func.lower(WazuhVulnerability.severity).in_(["critical", "critica", "crítica"]), 4),
    (sql_func.lower(WazuhVulnerability.severity).in_(["high", "alta"]), 3),
    (sql_func.lower(WazuhVulnerability.severity).in_(["medium", "media"]), 2),
    else_=1,
)

_SORTABLE_COLUMNS = {
    "cve_id": WazuhVulnerability.cve_id,
    "agent_name": WazuhVulnerability.agent_name,
    "package_name": WazuhVulnerability.package_name,
    "score_base": WazuhVulnerability.score_base,
    "first_seen": WazuhVulnerability.first_seen,
    "last_seen": WazuhVulnerability.last_seen,
    "connection_name": WazuhVulnerability.connection_id,
    "severity": _SEVERITY_RANK,
}


def _apply_vuln_filters(
    query,
    connection_id,
    agents,
    cves,
    packages,
    severities,
    status,
    score_min,
    score_max,
    search,
):
    if connection_id:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)
    if agents:
        query = query.filter(WazuhVulnerability.agent_name.in_(agents))
    if cves:
        query = query.filter(WazuhVulnerability.cve_id.in_(cves))
    if packages:
        query = query.filter(WazuhVulnerability.package_name.in_(packages))
    if severities:
        lowered = [s.lower() for s in severities]
        query = query.filter(sql_func.lower(WazuhVulnerability.severity).in_(lowered))
    if status:
        query = query.filter(WazuhVulnerability.status == status.upper())
    if score_min is not None:
        query = query.filter(WazuhVulnerability.score_base >= score_min)
    if score_max is not None:
        query = query.filter(WazuhVulnerability.score_base <= score_max)
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                WazuhVulnerability.cve_id.ilike(like),
                WazuhVulnerability.agent_name.ilike(like),
                WazuhVulnerability.package_name.ilike(like),
                WazuhVulnerability.description.ilike(like),
            )
        )
    return query


def _serialize_vuln(v: WazuhVulnerability, include_history: bool = False) -> dict:
    data = {
        "id": v.id,
        "connection_id": v.connection_id,
        "connection_name": v.connection.name if v.connection else None,
        "status": v.status,
        "agent_id": v.agent_id,
        "agent_name": v.agent_name,
        "os_full": v.os_full,
        "os_platform": v.os_platform,
        "os_version": v.os_version,
        "package_name": v.package_name,
        "package_version": v.package_version,
        "package_type": v.package_type,
        "package_arch": v.package_arch,
        "cve_id": v.cve_id,
        "severity": v.severity,
        "score_base": float(v.score_base) if v.score_base is not None else None,
        "score_version": v.score_version,
        "detected_at": v.detected_at,
        "published_at": v.published_at,
        "description": v.description,
        "reference": v.reference,
        "scanner_vendor": v.scanner_vendor,
        "first_seen": v.first_seen,
        "last_seen": v.last_seen,
    }
    if include_history:
        data["history"] = [
            {
                "id": h.id,
                "action": h.action,
                "details": h.details,
                "timestamp": h.timestamp,
            }
            for h in sorted(v.history, key=lambda h: h.timestamp)
        ]
    return data


@app.get("/vulns")
def list_vulns(
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    package_name: Optional[str] = None,
    severity: Optional[str] = None,
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
    """Lista paginada y filtrada server-side (sin N+1, sin traer historial).

    Toda la lógica de filtros, orden y paginación se ejecuta en la base de
    datos. El historial detallado se obtiene aparte vía /vulns/{id}/history.
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    query = db.query(WazuhVulnerability)
    query = _apply_vuln_filters(
        query,
        connection_id,
        _split_csv(agent_name),
        _split_csv(cve_id),
        _split_csv(package_name),
        _split_csv(severity),
        status,
        score_min,
        score_max,
        search,
    )

    total = query.order_by(None).count()

    sort_column = _SORTABLE_COLUMNS.get(sort_by, WazuhVulnerability.last_seen)
    direction = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    query = query.order_by(direction, WazuhVulnerability.id.asc())

    # Compatibilidad: si se pasa ?limit se respeta como tope simple
    if limit is not None:
        query = query.limit(limit)
        page_size = limit
        page = 1
    else:
        query = query.offset((page - 1) * page_size).limit(page_size)

    vulns = query.all()
    items = [_serialize_vuln(v) for v in vulns]

    return {
        "items": items,
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
    """Opciones de filtro precalculadas (DISTINCT en DB).

    Evita descargar 20k filas solo para poblar los dropdowns de la UI.
    """
    base = db.query  # alias for readability

    def distinct_values(column):
        q = db.query(column).filter(column.isnot(None), column != "")
        if connection_id:
            q = q.filter(WazuhVulnerability.connection_id == connection_id)
        return [row[0] for row in q.distinct().order_by(column.asc()).all()]

    severities = distinct_values(WazuhVulnerability.severity)

    return {
        "agents": distinct_values(WazuhVulnerability.agent_name),
        "cves": distinct_values(WazuhVulnerability.cve_id),
        "packages": distinct_values(WazuhVulnerability.package_name),
        "severities": [s.upper() for s in severities],
    }


@app.get("/vulns/{vuln_id}/history")
def vuln_history(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = (
        db.query(WazuhVulnerability)
        .options(selectinload(WazuhVulnerability.history))
        .filter(WazuhVulnerability.id == vuln_id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    return _serialize_vuln(vuln, include_history=True)


def _db_dialect(db: Session) -> str:
    return db.get_bind().dialect.name


def _filter_detections_by_connection(query, connection_id: Optional[int]):
    if connection_id is None:
        return query
    return query.join(VulnerabilityDetection.asset).join(Asset.manager).filter(
        Manager.legacy_connection_id == connection_id
    )


def _week_start(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    start = value - timedelta(days=value.weekday())
    return start.replace(hour=0, minute=0, second=0, microsecond=0)


def _weekly_trend_fallback(db: Session, connection_id: Optional[int]):
    query = db.query(VulnerabilityDetection).filter(
        VulnerabilityDetection.status == "Detected"
    )
    query = _filter_detections_by_connection(query, connection_id)

    buckets = {}
    for detection in query.all():
        bucket = _week_start(detection.timestamp)
        buckets[bucket] = buckets.get(bucket, 0) + 1

    return [
        {"semana": bucket.isoformat(), "total_vulnerabilidades": total}
        for bucket, total in sorted(buckets.items(), key=lambda item: item[0])
    ]


@app.get("/vulns/evolution/weekly")
def weekly_vulnerability_trend(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if _db_dialect(db) == "postgresql":
        rows = db.execute(text("""
            SELECT time_bucket('1 week', vd.timestamp) AS semana,
                   count(*) AS total_vulnerabilidades
            FROM vulnerability_detections vd
            JOIN assets a ON a.id = vd.asset_id
            JOIN managers m ON m.id = a.manager_id
            WHERE vd.status = 'Detected'
              AND (:connection_id IS NULL OR m.legacy_connection_id = :connection_id)
            GROUP BY semana
            ORDER BY semana
        """), {"connection_id": connection_id}).mappings().all()
        return [
            {
                "semana": row["semana"].isoformat() if row["semana"] else None,
                "total_vulnerabilidades": row["total_vulnerabilidades"],
            }
            for row in rows
        ]

    return _weekly_trend_fallback(db, connection_id)


@app.get("/vulns/evolution/top-assets")
def top_vulnerable_assets(
    days: int = 7,
    limit: int = 5,
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Servidores con más vulnerabilidades activas (CVEs distintos).

    Se calcula sobre el inventario actual de ``wazuh_vulnerabilities`` (estado
    ACTIVE) en vez de los eventos de detección dentro de una ventana de días.
    Así el panel siempre reporta mientras existan vulnerabilidades activas,
    sin depender de que el @timestamp de Wazuh caiga dentro de los últimos N días.
    """
    limit = max(1, min(limit, 50))

    rows = db.query(
        WazuhVulnerability.agent_name.label("hostname"),
        sql_func.count(sql_func.distinct(WazuhVulnerability.cve_id)).label("total"),
    ).filter(WazuhVulnerability.status == "ACTIVE")

    if connection_id is not None:
        rows = rows.filter(WazuhVulnerability.connection_id == connection_id)

    rows = (
        rows.group_by(WazuhVulnerability.agent_name)
        .order_by(text("total DESC"))
        .limit(limit)
        .all()
    )
    return [
        {"hostname": hostname or "Sin hostname", "total": total}
        for hostname, total in rows
    ]


@app.get("/vulns/evolution/summary")
def vulnerability_evolution_summary(
    connection_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    active_query = db.query(WazuhVulnerability).filter(WazuhVulnerability.status == "ACTIVE")
    resolved_query = db.query(WazuhVulnerability).filter(WazuhVulnerability.status == "RESOLVED")

    if connection_id is not None:
        active_query = active_query.filter(WazuhVulnerability.connection_id == connection_id)
        resolved_query = resolved_query.filter(WazuhVulnerability.connection_id == connection_id)

    detections_query = db.query(VulnerabilityDetection)
    detections_query = _filter_detections_by_connection(detections_query, connection_id)

    assets_query = db.query(Asset)
    if connection_id is not None:
        assets_query = assets_query.join(Asset.manager).filter(
            Manager.legacy_connection_id == connection_id
        )

    # Última sincronización: la más reciente entre todas las conexiones del filtro
    sync_query = db.query(sql_func.max(WazuhConnection.last_sync_at))
    if connection_id is not None:
        sync_query = sync_query.filter(WazuhConnection.id == connection_id)
    last_sync_at = sync_query.scalar()

    return {
        "active_vulnerabilities": active_query.count(),
        "resolved_vulnerabilities": resolved_query.count(),
        "assets": assets_query.count(),
        "detection_events": detections_query.count(),
        "last_sync_at": last_sync_at.isoformat() if last_sync_at else None,
    }


# Configuración de periodos para la línea de trazabilidad
_PERIOD_CONFIG = {
    "24h": {"delta": timedelta(days=1), "bucket": "1 hour"},
    "7d": {"delta": timedelta(days=7), "bucket": "1 day"},
    "30d": {"delta": timedelta(days=30), "bucket": "1 day"},
    "90d": {"delta": timedelta(days=90), "bucket": "1 week"},
    "all": {"delta": timedelta(days=3650), "bucket": "1 week"},
}


def _traceability_timeline_fallback(db, connection_id, start, end):
    """Agregación en Python para motores sin TimescaleDB (tests con SQLite)."""
    query = db.query(VulnerabilityDetection).filter(
        VulnerabilityDetection.timestamp >= start,
        VulnerabilityDetection.timestamp <= end,
    )
    query = _filter_detections_by_connection(query, connection_id)

    buckets = {}
    for detection in query.all():
        bucket = _week_start(detection.timestamp).isoformat()
        slot = buckets.setdefault(bucket, {"nuevas": 0, "reemergidas": 0, "remediadas": 0})
        if detection.status == "Detected":
            slot["nuevas"] += 1
        elif detection.status == "Re-emerged":
            slot["reemergidas"] += 1
        elif detection.status == "Resolved":
            slot["remediadas"] += 1

    return [
        {"bucket": bucket, **counts}
        for bucket, counts in sorted(buckets.items(), key=lambda item: item[0])
    ]


@app.get("/vulns/evolution/timeline")
def traceability_timeline(
    period: str = "30d",
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Línea de trazabilidad: nuevas vs. reemergidas vs. remediadas por bucket.

    Procesamiento temporal hecho 100% en backend. Sin filtros extra usa el
    stored procedure sp_traceability_timeline; con filtros de agente/CVE usa
    una consulta parametrizada equivalente (ambas sobre la hypertable).
    """
    config = _PERIOD_CONFIG.get(period, _PERIOD_CONFIG["30d"])
    end = datetime.now(timezone.utc)
    start = end - config["delta"]
    agents = _split_csv(agent_name)
    cves = _split_csv(cve_id)

    if _db_dialect(db) != "postgresql":
        return {
            "period": period,
            "bucket": config["bucket"],
            "points": _traceability_timeline_fallback(db, connection_id, start, end),
        }

    if not agents and not cves:
        rows = db.execute(
            text("""
                SELECT bucket, nuevas, reemergidas, remediadas
                FROM sp_traceability_timeline(
                    :connection_id, CAST(:bucket AS INTERVAL), :start, :end
                )
            """),
            {
                "connection_id": connection_id,
                "bucket": config["bucket"],
                "start": start,
                "end": end,
            },
        ).mappings().all()
    else:
        rows = db.execute(
            text("""
                SELECT
                    time_bucket(CAST(:bucket AS INTERVAL), vd.timestamp) AS bucket,
                    count(*) FILTER (WHERE vd.status = 'Detected')   AS nuevas,
                    count(*) FILTER (WHERE vd.status = 'Re-emerged') AS reemergidas,
                    count(*) FILTER (WHERE vd.status = 'Resolved')   AS remediadas
                FROM vulnerability_detections vd
                JOIN assets a   ON a.id = vd.asset_id
                JOIN managers m ON m.id = a.manager_id
                WHERE vd.timestamp >= :start AND vd.timestamp <= :end
                  AND (:connection_id IS NULL OR m.legacy_connection_id = :connection_id)
                  AND (:has_agents = FALSE OR a.hostname = ANY(:agents))
                  AND (:has_cves = FALSE OR vd.cve_id = ANY(:cves))
                GROUP BY bucket
                ORDER BY bucket
            """),
            {
                "connection_id": connection_id,
                "bucket": config["bucket"],
                "start": start,
                "end": end,
                "has_agents": bool(agents),
                "agents": agents,
                "has_cves": bool(cves),
                "cves": cves,
            },
        ).mappings().all()

    return {
        "period": period,
        "bucket": config["bucket"],
        "points": [
            {
                "bucket": row["bucket"].isoformat() if row["bucket"] else None,
                "nuevas": row["nuevas"],
                "reemergidas": row["reemergidas"],
                "remediadas": row["remediadas"],
            }
            for row in rows
        ],
    }


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
    """Detalle (drill-down) de los eventos de detección dentro de un bucket.

    Se carga bajo demanda al abrir un slot, de modo que la línea de tiempo
    nunca descarga los 20k+ registros completos.
    """
    limit = max(1, min(limit, 2000))

    query = (
        db.query(
            VulnerabilityDetection.timestamp.label("timestamp"),
            VulnerabilityDetection.status.label("status"),
            VulnerabilityDetection.cve_id.label("cve_id"),
            VulnerabilityDetection.package_name.label("package_name"),
            VulnerabilityDetection.package_version.label("package_version"),
            Asset.hostname.label("hostname"),
            Manager.nombre.label("connection_name"),
            VulnerabilityCatalog.severity.label("severity"),
        )
        .join(Asset, Asset.id == VulnerabilityDetection.asset_id)
        .join(Manager, Manager.id == Asset.manager_id)
        .outerjoin(
            VulnerabilityCatalog,
            VulnerabilityCatalog.cve_id == VulnerabilityDetection.cve_id,
        )
        .filter(
            VulnerabilityDetection.timestamp >= bucket_start,
            VulnerabilityDetection.timestamp <= bucket_end,
        )
    )

    if connection_id:
        query = query.filter(Manager.legacy_connection_id == connection_id)
    agents = _split_csv(agent_name)
    if agents:
        query = query.filter(Asset.hostname.in_(agents))
    cves = _split_csv(cve_id)
    if cves:
        query = query.filter(VulnerabilityDetection.cve_id.in_(cves))

    rows = query.order_by(VulnerabilityDetection.timestamp.desc()).limit(limit).all()

    status_map = {"Resolved": "RESOLVED"}
    label_map = {
        "Detected": "DETECTED",
        "Re-emerged": "REOPENED",
        "Resolved": "RESOLVED",
    }
    return [
        {
            "id": f"{row.cve_id}-{row.hostname}-{row.timestamp.isoformat()}",
            "connection_name": row.connection_name,
            "agent_name": row.hostname,
            "cve_id": row.cve_id,
            "severity": row.severity,
            "package_name": row.package_name,
            "package_version": row.package_version,
            "timeline_event_at": row.timestamp,
            "timeline_event_label": label_map.get(row.status, row.status),
            "detected_at": None,
            "first_seen": row.timestamp,
            "last_seen": row.timestamp,
            "status": status_map.get(row.status, "ACTIVE"),
            "resolved_at": row.timestamp if row.status == "Resolved" else None,
        }
        for row in rows
    ]


@app.get("/vulns/evolution/traceability-summary")
def traceability_summary(
    connection_id: Optional[int] = None,
    new_window_days: int = 7,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Resumen del algoritmo de trazabilidad: Nuevas / Persistentes / Remediadas."""
    if _db_dialect(db) == "postgresql":
        row = db.execute(
            text("""
                SELECT nuevas, persistentes, remediadas, total_activas
                FROM sp_traceability_summary(
                    :connection_id, CAST(:window AS INTERVAL)
                )
            """),
            {"connection_id": connection_id, "window": f"{new_window_days} days"},
        ).mappings().first()
        return {
            "nuevas": row["nuevas"] if row else 0,
            "persistentes": row["persistentes"] if row else 0,
            "remediadas": row["remediadas"] if row else 0,
            "total_activas": row["total_activas"] if row else 0,
        }

    # Fallback ORM
    cutoff = datetime.now(timezone.utc) - timedelta(days=new_window_days)
    active_q = db.query(WazuhVulnerability).filter(WazuhVulnerability.status == "ACTIVE")
    resolved_q = db.query(WazuhVulnerability).filter(WazuhVulnerability.status == "RESOLVED")
    if connection_id:
        active_q = active_q.filter(WazuhVulnerability.connection_id == connection_id)
        resolved_q = resolved_q.filter(WazuhVulnerability.connection_id == connection_id)

    nuevas = active_q.filter(WazuhVulnerability.first_seen >= cutoff).count()
    total_activas = active_q.count()
    return {
        "nuevas": nuevas,
        "persistentes": total_activas - nuevas,
        "remediadas": resolved_q.count(),
        "total_activas": total_activas,
    }


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


@app.get("/vulns/evolution/threats")
def threat_spans(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    connection_id: Optional[int] = None,
    agent_name: Optional[str] = None,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Línea de tiempo tipo Gantt: una barra por amenaza (vulnerabilidad única).

    Cada elemento representa un registro distinto de ``wazuh_vulnerabilities``
    (servidor + paquete + CVE) con su intervalo de vida:

    * ``start`` = first_seen (cuándo se detectó por primera vez).
    * ``end``   = last_seen si está RESOLVED; ``null`` si sigue ACTIVE (en curso).

    El conteo (``total`` / ``active`` / ``resolved``) es de amenazas DISTINTAS,
    no de eventos de detección: si una amenaza se actualizó 6 veces, cuenta 1.

    El frontend recorta (clamp) cada barra al rango visible [start, end].
    Consulta directa e indexada sobre ``wazuh_vulnerabilities`` (rápida).
    """
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)

    now = datetime.now(timezone.utc)
    end = _ensure_utc(end) if end else now
    start = _ensure_utc(start) if start else (end - timedelta(days=30))

    # Filtro base por dimensiones (sin tiempo): define el universo de amenazas.
    base = _apply_vuln_filters(
        db.query(WazuhVulnerability),
        connection_id,
        _split_csv(agent_name),
        _split_csv(cve_id),
        [],  # packages
        _split_csv(severity),
        None,  # status (lo manejamos aquí)
        None,
        None,
        None,
    )

    # Una amenaza "aparece" en el rango si sigue activa o si su última
    # actividad (last_seen) cae dentro/después del inicio del rango, y su
    # primera detección no es posterior al fin del rango.
    in_range = base.filter(
        WazuhVulnerability.first_seen <= end,
        or_(
            WazuhVulnerability.status == "ACTIVE",
            WazuhVulnerability.last_seen >= start,
        ),
    )

    total = in_range.order_by(None).count()
    active = in_range.filter(WazuhVulnerability.status == "ACTIVE").order_by(None).count()
    resolved = total - active

    rows = (
        in_range.order_by(
            _SEVERITY_RANK.desc(),
            WazuhVulnerability.first_seen.asc(),
            WazuhVulnerability.id.asc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "connection_id": v.connection_id,
            "connection_name": v.connection.name if v.connection else None,
            "agent_name": v.agent_name,
            "package_name": v.package_name,
            "package_version": v.package_version,
            "severity": v.severity,
            "score_base": float(v.score_base) if v.score_base is not None else None,
            "status": v.status,
            "start": v.first_seen.isoformat() if v.first_seen else None,
            "end": (
                v.last_seen.isoformat()
                if (v.status == "RESOLVED" and v.last_seen)
                else None
            ),
            "last_seen": v.last_seen.isoformat() if v.last_seen else None,
        }
        for v in rows
    ]

    return {
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        "total": total,
        "active": active,
        "resolved": resolved,
        "returned": len(items),
        "limit": limit,
        "offset": offset,
        "items": items,
    }
