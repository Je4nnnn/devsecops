# app/main.py
import re
import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from dotenv import set_key, find_dotenv
from sqlalchemy.orm import Session
from typing import List, Annotated, Optional
from pydantic import BaseModel
from sqlalchemy import text, func as sql_func
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


initialize_timescale_storage()

CONNECTION_NOT_FOUND = "Conexión no encontrada"


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

    raw_vulns = fetch_all_vulns(
        conn.indexer_url, conn.wazuh_user, decrypt(conn.wazuh_password)
    )

    count = process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
    db.commit()

    return {"synced": count, "connection": conn.name}


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


def process_wazuh_vulnerabilities(db: Session, conn_id: int, raw_vulns: list) -> int:
    conn = db.query(WazuhConnection).filter(WazuhConnection.id == conn_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail=CONNECTION_NOT_FOUND)

    count = 0
    seen_vuln_ids = set()
    scan_timestamp = datetime.now(timezone.utc)
    manager = _get_or_create_manager(db, conn)

    active_vulns_in_db = db.query(WazuhVulnerability).filter_by(connection_id=conn_id, status="ACTIVE").all()
    active_vuln_dict = {v.id: v for v in active_vulns_in_db}

    for v in raw_vulns:
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

        _record_detection_event(
            db,
            asset.id,
            catalog.cve_id,
            event_status,
            pkg,
            scan_timestamp,
        )
        count += 1

    _resolve_missing_vulns(db, manager, active_vuln_dict, seen_vuln_ids, scan_timestamp)
    return count


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
    conns = db.query(WazuhConnection).filter(WazuhConnection.is_active == True).all()
    results = []

    for conn in conns:
        try:
            raw_vulns = fetch_all_vulns(
                conn.indexer_url,
                conn.wazuh_user,
                decrypt(conn.wazuh_password),
            )

            count = process_wazuh_vulnerabilities(db, conn.id, raw_vulns)
            db.commit()

            results.append({"connection": conn.name, "synced": count, "ok": True})
        except Exception as e:
            db.rollback()
            results.append({"connection": conn.name, "ok": False, "error": str(e)})

    return results


@app.get("/vulns")
def list_vulns(
    limit: Optional[int] = None,
    connection_id: int = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(WazuhVulnerability)
    
    if connection_id:
        query = query.filter(WazuhVulnerability.connection_id == connection_id)

    if limit is not None:
        query = query.limit(limit)

    vulns = query.all()

    return [
        {
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
            "score_base": float(v.score_base) if v.score_base else None,
            "score_version": v.score_version,
            "detected_at": v.detected_at,
            "published_at": v.published_at,
            "description": v.description,
            "reference": v.reference,
            "scanner_vendor": v.scanner_vendor,
            "first_seen": v.first_seen,
            "last_seen": v.last_seen,
            "history": [
                {
                    "id": h.id,
                    "action": h.action,
                    "details": h.details,
                    "timestamp": h.timestamp,
                }
                for h in sorted(v.history, key=lambda h: h.timestamp)
            ],
        }
        for v in vulns
    ]


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
    days = max(1, min(days, 365))
    limit = max(1, min(limit, 50))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    rows = db.query(
        Asset.hostname.label("hostname"),
        sql_func.count(sql_func.distinct(VulnerabilityDetection.cve_id)).label("total"),
    ).join(
        VulnerabilityDetection, VulnerabilityDetection.asset_id == Asset.id
    ).join(
        Manager, Manager.id == Asset.manager_id
    ).filter(
        VulnerabilityDetection.timestamp >= since,
        VulnerabilityDetection.status.in_(["Detected", "Re-emerged"]),
    )

    if connection_id is not None:
        rows = rows.filter(Manager.legacy_connection_id == connection_id)

    rows = rows.group_by(Asset.hostname).order_by(text("total DESC")).limit(limit).all()
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

    return {
        "active_vulnerabilities": active_query.count(),
        "resolved_vulnerabilities": resolved_query.count(),
        "assets": assets_query.count(),
        "detection_events": detections_query.count(),
    }
