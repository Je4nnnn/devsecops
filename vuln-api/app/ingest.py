# app/ingest.py
"""Ingesta de vulnerabilidades de Wazuh hacia el modelo en estrella.

Carga en memoria las dimensiones de la conexión una sola vez y luego resuelve
cada documento contra esos diccionarios: sin esto la sincronización de 20k+
documentos haría cientos de miles de SELECT (N+1).
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import insert, select

from .models import (
    AgentGroup,
    Asset,
    AssetGroupMember,
    FindingHistory,
    OperatingSystem,
    Package,
    SEVERITY_RANKS,
    VulnerabilityCatalog,
    VulnerabilityDetection,
    VulnerabilityFinding,
    WazuhConnection,
)

DETECTION_CHUNK = 1000


# ---------------------------------------------------------------------------
# Normalización de los documentos de Wazuh
# ---------------------------------------------------------------------------
def normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "Unknown"
    normalized = value.strip().lower()
    if normalized in {"critical", "critica", "crítica"}:
        return "Critical"
    if normalized in {"high", "alta"}:
        return "High"
    if normalized in {"medium", "media"}:
        return "Medium"
    if normalized in {"low", "baja"}:
        return "Low"
    return "Unknown"


def parse_timestamp(value, fallback: Optional[datetime] = None) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return fallback


def _scan_timestamp(doc: dict, fallback: datetime) -> datetime:
    """@timestamp del documento; si falta, la fecha de detección; si no, ahora."""
    parsed = parse_timestamp(doc.get("@timestamp"))
    if parsed:
        return parsed
    vuln = doc.get("vulnerability") or {}
    return parse_timestamp(vuln.get("detected_at"), fallback)


def extract_groups(agent: dict, doc: dict) -> list:
    """Grupos del agente Wazuh. Acepta lista o string, en agent o host."""
    host = doc.get("host") or {}
    raw = (
        agent.get("groups")
        or agent.get("group")
        or host.get("groups")
        or doc.get("agent_groups")
    )
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = raw.split(",")
    return sorted({str(item).strip() for item in raw if str(item).strip()})


def extract_ip(agent: dict, doc: dict) -> Optional[str]:
    host = doc.get("host") or {}
    value = agent.get("ip") or host.get("ip") or doc.get("ip")
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _score_base(vuln: dict):
    score = (vuln.get("score") or {}).get("base")
    return None if score in ("", None) else score


# ---------------------------------------------------------------------------
# Cachés de dimensiones para una corrida de sincronización
# ---------------------------------------------------------------------------
class _DimensionCache:
    """Diccionarios de dimensiones precargados para evitar el N+1."""

    def __init__(self, db, connection_id: int):
        self.db = db
        self.connection_id = connection_id

        self.os = {
            (o.platform, o.version, o.full): o
            for o in db.execute(select(OperatingSystem)).scalars()
        }
        self.packages = {
            (p.name, p.version, p.type, p.architecture): p
            for p in db.execute(select(Package)).scalars()
        }
        self.catalog = {
            c.cve_id: c for c in db.execute(select(VulnerabilityCatalog)).scalars()
        }
        self.assets = {
            a.wazuh_agent_id: a
            for a in db.execute(
                select(Asset).where(Asset.connection_id == connection_id)
            ).scalars()
        }
        self.groups = {
            g.name: g
            for g in db.execute(
                select(AgentGroup).where(AgentGroup.connection_id == connection_id)
            ).scalars()
        }
        asset_ids = [a.id for a in self.assets.values()]
        self.memberships = set()
        if asset_ids:
            self.memberships = {
                (m.asset_id, m.group_id)
                for m in db.execute(
                    select(AssetGroupMember).where(
                        AssetGroupMember.asset_id.in_(asset_ids)
                    )
                ).scalars()
            }
        self.findings = {}
        if asset_ids:
            for f in db.execute(
                select(VulnerabilityFinding).where(
                    VulnerabilityFinding.asset_id.in_(asset_ids)
                )
            ).scalars():
                self.findings[(f.asset_id, f.cve_id, f.package_id)] = f

    # -- Dimensiones -------------------------------------------------------
    def operating_system(self, osinfo: dict) -> Optional[OperatingSystem]:
        platform = (osinfo.get("platform") or "").strip()
        version = (osinfo.get("version") or "").strip()
        full = (osinfo.get("full") or "").strip()
        if not (platform or version or full):
            return None

        key = (platform, version, full)
        found = self.os.get(key)
        if not found:
            found = OperatingSystem(
                platform=platform,
                version=version,
                full=full,
                name=(osinfo.get("name") or platform),
            )
            self.db.add(found)
            self.db.flush()
            self.os[key] = found
        return found

    def package(self, pkg: dict) -> Package:
        key = (
            (pkg.get("name") or "").strip(),
            (pkg.get("version") or "").strip(),
            (pkg.get("type") or "").strip(),
            (pkg.get("architecture") or "").strip(),
        )
        found = self.packages.get(key)
        if not found:
            found = Package(
                name=key[0], version=key[1], type=key[2], architecture=key[3]
            )
            self.db.add(found)
            self.db.flush()
            self.packages[key] = found
        return found

    def catalog_entry(self, vuln: dict) -> tuple:
        """Devuelve (entrada de catálogo, severidad anterior si cambió)."""
        cve_id = vuln.get("id")
        severity = normalize_severity(vuln.get("severity"))
        entry = self.catalog.get(cve_id)
        previous = None

        if not entry:
            entry = VulnerabilityCatalog(cve_id=cve_id)
            self.db.add(entry)
            self.catalog[cve_id] = entry
        elif entry.severity != severity:
            previous = entry.severity

        entry.severity = severity
        entry.severity_rank = SEVERITY_RANKS.get(severity, 0)
        entry.cvss_score = _score_base(vuln)
        entry.cvss_version = (vuln.get("score") or {}).get("version")
        entry.description = vuln.get("description") or entry.description
        entry.reference = vuln.get("reference") or entry.reference
        entry.published_at = parse_timestamp(vuln.get("published_at"), entry.published_at)
        return entry, previous

    def asset(self, agent: dict, doc: dict, osinfo: dict, seen_at: datetime) -> Asset:
        agent_id = str(agent.get("id") or "unknown")
        found = self.assets.get(agent_id)
        if not found:
            found = Asset(
                connection_id=self.connection_id,
                wazuh_agent_id=agent_id,
                first_seen=seen_at,
            )
            self.db.add(found)
            self.db.flush()
            self.assets[agent_id] = found

        found.hostname = agent.get("name") or found.hostname
        found.ip_address = extract_ip(agent, doc) or found.ip_address
        found.last_seen = seen_at

        operating_system = self.operating_system(osinfo)
        if operating_system is not None:
            found.os_id = operating_system.id
        return found

    def link_groups(self, asset: Asset, names: list) -> None:
        for name in names:
            group = self.groups.get(name)
            if not group:
                group = AgentGroup(connection_id=self.connection_id, name=name)
                self.db.add(group)
                self.db.flush()
                self.groups[name] = group

            key = (asset.id, group.id)
            if key not in self.memberships:
                self.db.add(AssetGroupMember(asset_id=asset.id, group_id=group.id))
                self.memberships.add(key)


# ---------------------------------------------------------------------------
# Eventos de detección (inserción masiva idempotente)
# ---------------------------------------------------------------------------
def _flush_detections(db, rows: list) -> None:
    """Inserta eventos ignorando duplicados (misma amenaza, mismo instante)."""
    if not rows:
        return

    dialect = db.get_bind().dialect.name
    table = VulnerabilityDetection.__table__

    for start in range(0, len(rows), DETECTION_CHUNK):
        chunk = rows[start : start + DETECTION_CHUNK]
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            db.execute(pg_insert(table).values(chunk).on_conflict_do_nothing())
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            db.execute(sqlite_insert(table).values(chunk).on_conflict_do_nothing())
        else:
            db.execute(insert(table).values(chunk))
    rows.clear()


# ---------------------------------------------------------------------------
# Proceso principal
# ---------------------------------------------------------------------------
def process_wazuh_vulnerabilities(
    db, conn_id: int, raw_vulns, progress_cb=None, agent_groups=None
) -> int:
    """Sincroniza una colección o flujo ``Sized`` de Wazuh.

    La ingesta consume el iterable una sola vez y devuelve el número procesado.
    """
    conn = db.get(WazuhConnection, conn_id)
    if conn is None:
        raise ValueError("Conexión no encontrada")

    scan_ts = datetime.now(timezone.utc)
    cache = _DimensionCache(db, conn_id)
    detections = []
    seen_finding_keys = set()
    count = 0
    total = len(raw_vulns)

    for index, doc in enumerate(raw_vulns):
        if progress_cb and index % 200 == 0:
            progress_cb(index, total)

        vuln = doc.get("vulnerability") or {}
        if not vuln.get("id"):
            continue

        agent = doc.get("agent") or {}
        osinfo = (doc.get("host") or {}).get("os") or {}
        pkg = doc.get("package") or {}
        observed_at = _scan_timestamp(doc, scan_ts)

        asset = cache.asset(agent, doc, osinfo, scan_ts)
        cache.link_groups(asset, extract_groups(agent, doc))
        package = cache.package(pkg)
        catalog, previous_severity = cache.catalog_entry(vuln)

        key = (asset.id, catalog.cve_id, package.id)
        finding = cache.findings.get(key)

        if finding is None:
            finding = VulnerabilityFinding(
                asset_id=asset.id,
                cve_id=catalog.cve_id,
                package_id=package.id,
                status="ACTIVE",
                first_seen=observed_at,
                last_seen=scan_ts,
                detected_at=parse_timestamp(vuln.get("detected_at")),
            )
            db.add(finding)
            db.flush()
            cache.findings[key] = finding
            db.add(FindingHistory(
                finding_id=finding.id,
                action="DETECTED",
                details="Vulnerabilidad identificada por primera vez",
            ))
            event_status = "Detected"
        elif finding.status == "RESOLVED":
            finding.status = "ACTIVE"
            finding.resolved_at = None
            db.add(FindingHistory(
                finding_id=finding.id,
                action="REOPENED",
                details="La vulnerabilidad fue detectada nuevamente por Wazuh",
            ))
            event_status = "Re-emerged"
        else:
            event_status = "Detected"

        if previous_severity:
            db.add(FindingHistory(
                finding_id=finding.id,
                action="SEVERITY_CHANGED",
                details=f"Severidad cambió de {previous_severity} a {catalog.severity}",
            ))

        finding.score_base = _score_base(vuln)
        finding.score_version = (vuln.get("score") or {}).get("version")
        finding.scanner_vendor = (vuln.get("scanner") or {}).get("vendor")
        finding.last_seen = scan_ts

        seen_finding_keys.add(key)
        detections.append({
            "timestamp": observed_at,
            "finding_id": finding.id,
            "status": event_status,
        })
        if len(detections) >= DETECTION_CHUNK:
            _flush_detections(db, detections)
        count += 1

    _resolve_missing(db, cache, seen_finding_keys, scan_ts, detections)
    if agent_groups is not None:
        _replace_agent_groups(db, cache, agent_groups)
    _flush_detections(db, detections)

    if progress_cb:
        progress_cb(total, total)

    conn.last_sync_at = scan_ts
    return count


def _replace_agent_groups(db, cache, agent_groups: dict) -> None:
    """Reemplaza membresías con el estado actual de ``wazuh-monitoring-*``."""
    asset_ids = [asset.id for asset in cache.assets.values()]
    if asset_ids:
        db.query(AssetGroupMember).filter(
            AssetGroupMember.asset_id.in_(asset_ids)
        ).delete(synchronize_session=False)

    db.query(AgentGroup).filter(
        AgentGroup.connection_id == cache.connection_id
    ).delete(synchronize_session=False)
    db.flush()

    cache.groups = {}
    cache.memberships = set()
    for agent_id, raw_names in agent_groups.items():
        asset = cache.assets.get(str(agent_id))
        if asset is None:
            continue
        if isinstance(raw_names, str):
            raw_names = raw_names.split(",")
        names = sorted(
            {str(name).strip() for name in (raw_names or []) if str(name).strip()}
        )
        cache.link_groups(asset, names)


def _resolve_missing(db, cache, seen_keys, scan_ts, detections) -> None:
    """Marca como RESUELTAS las amenazas activas que Wazuh ya no reporta."""
    for key, finding in cache.findings.items():
        if key in seen_keys or finding.status != "ACTIVE":
            continue
        finding.status = "RESOLVED"
        finding.resolved_at = scan_ts
        finding.last_seen = scan_ts
        db.add(FindingHistory(
            finding_id=finding.id,
            action="RESOLVED",
            details="Ya no es reportada por el agente (probablemente parcheada)",
        ))
        detections.append({
            "timestamp": scan_ts,
            "finding_id": finding.id,
            "status": "Resolved",
        })


def delete_connection_data(db, conn_id: int) -> None:
    """Borra en bloque todo lo derivado de una conexión (orden de FK)."""
    asset_ids = [
        row[0]
        for row in db.execute(
            select(Asset.id).where(Asset.connection_id == conn_id)
        ).all()
    ]

    if asset_ids:
        finding_ids = [
            row[0]
            for row in db.execute(
                select(VulnerabilityFinding.id).where(
                    VulnerabilityFinding.asset_id.in_(asset_ids)
                )
            ).all()
        ]
        if finding_ids:
            db.query(VulnerabilityDetection).filter(
                VulnerabilityDetection.finding_id.in_(finding_ids)
            ).delete(synchronize_session=False)
            db.query(FindingHistory).filter(
                FindingHistory.finding_id.in_(finding_ids)
            ).delete(synchronize_session=False)
            db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.id.in_(finding_ids)
            ).delete(synchronize_session=False)

        db.query(AssetGroupMember).filter(
            AssetGroupMember.asset_id.in_(asset_ids)
        ).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.id.in_(asset_ids)).delete(synchronize_session=False)

    db.query(AgentGroup).filter(AgentGroup.connection_id == conn_id).delete(
        synchronize_session=False
    )
