# app/models.py
"""Modelo de datos del agregador de vulnerabilidades.

Diseño en estrella (star schema) pensado para escalar a millones de filas:

    wazuh_connections (el "manager" Wazuh: config + credenciales)
        ├──< agent_groups                     (grupos de agentes del manager)
        └──< assets                           (agentes/servidores monitoreados)
                ├──< asset_group_members      (N:M asset <-> grupo)
                └──< vulnerability_findings   (HECHO: estado actual por asset+CVE+paquete)
                          ├──< finding_history        (bitácora de cambios de estado)
                          └──< vulnerability_detections (hypertable de eventos en el tiempo)

    Dimensiones compartidas (una fila por valor único, referenciadas por FK):
        operating_systems · packages · vulnerability_catalog

Reglas que evitan identificadores repetidos y datos duplicados:

* Un único identificador por entidad. El "manager" vive SOLO en
  ``wazuh_connections``; antes existía además ``managers`` con su propio id y
  un puente ``legacy_connection_id`` — esa duplicación se eliminó.
* Los textos que se repiten miles de veces (nombre de paquete, versión, S.O.)
  viven una sola vez en su tabla dimensión y los hechos guardan la FK.
* La severidad/criticidad es un atributo del CVE y vive solo en
  ``vulnerability_catalog``; los hallazgos guardan el score CVSS observado.
* ``vulnerability_detections`` no repite CVE/paquete/asset: se llega a ellos
  navegando ``finding_id``.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .db import Base

# ---------------------------------------------------------------------------
# Vocabularios controlados (CHECK en vez de ENUM nativo: migrar un ENUM de
# PostgreSQL exige ALTER TYPE y bloquea; un CHECK se cambia sin downtime).
# ---------------------------------------------------------------------------
SEVERITY_VALUES = ("Critical", "High", "Medium", "Low", "Unknown")
SEVERITY_RANKS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
FINDING_STATUS_VALUES = ("ACTIVE", "RESOLVED")
DETECTION_STATUS_VALUES = ("Detected", "Re-emerged", "Resolved")

# En SQLite (tests) BIGINT no es alias de rowid y no autoincrementa; la variante
# INTEGER mantiene el mismo comportamiento en ambos motores.
BigIntPk = BigInteger().with_variant(Integer, "sqlite")


# ---------------------------------------------------------------------------
# Seguridad / auditoría
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)
    is_default_password = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    interactions = relationship("UserInteraction", back_populates="user")


class UserInteraction(Base):
    __tablename__ = "user_interactions"

    id = Column(BigIntPk, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    endpoint = Column(String, index=True)
    method = Column(String)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="interactions")


# ---------------------------------------------------------------------------
# Origen de datos: un manager Wazuh = una conexión
# ---------------------------------------------------------------------------
class WazuhConnection(Base):
    """Manager Wazuh. Es la ÚNICA representación del origen de datos."""

    __tablename__ = "wazuh_connections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    indexer_url = Column(String, nullable=False)
    wazuh_user = Column(String, nullable=False)
    wazuh_password = Column(String, nullable=False)  # cifrado en reposo (crypto.py)
    is_active = Column(Boolean, default=True)
    tested = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    assets = relationship(
        "Asset", back_populates="connection", cascade="all, delete-orphan"
    )
    groups = relationship(
        "AgentGroup", back_populates="connection", cascade="all, delete-orphan"
    )


class AgentGroup(Base):
    """Grupo de agentes de Wazuh (``agent.groups``)."""

    __tablename__ = "agent_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    connection_id = Column(
        Integer,
        ForeignKey("wazuh_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String, nullable=False)

    connection = relationship("WazuhConnection", back_populates="groups")
    members = relationship(
        "AssetGroupMember", back_populates="group", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("connection_id", "name", name="uq_agent_group_conn_name"),
    )


# ---------------------------------------------------------------------------
# Dimensiones compartidas
# ---------------------------------------------------------------------------
class OperatingSystem(Base):
    """Sistema operativo normalizado. Se repite en miles de assets: una fila."""

    __tablename__ = "operating_systems"

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform = Column(String, nullable=False, default="")
    name = Column(String, nullable=False, default="")
    version = Column(String, nullable=False, default="")
    full = Column(String, nullable=False, default="")

    __table_args__ = (
        UniqueConstraint("platform", "version", "full", name="uq_os_identity"),
        Index("idx_os_platform", "platform"),
    )


class Package(Base):
    """Paquete de software afectado. Tabla dimensión pedida en la entrega."""

    __tablename__ = "packages"

    id = Column(BigIntPk, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False, default="")
    type = Column(String, nullable=False, default="")
    architecture = Column(String, nullable=False, default="")

    findings = relationship("VulnerabilityFinding", back_populates="package")

    __table_args__ = (
        UniqueConstraint(
            "name", "version", "type", "architecture", name="uq_package_identity"
        ),
        Index("idx_package_name", "name"),
    )


class VulnerabilityCatalog(Base):
    """Catálogo de CVEs. La criticidad vive AQUÍ y en ningún otro lugar."""

    __tablename__ = "vulnerability_catalog"

    cve_id = Column(String, primary_key=True)
    severity = Column(String, nullable=False, default="Unknown")
    # Puntaje numérico de criticidad (0..4) derivado de severity: permite
    # filtrar/ordenar por criticidad con un índice, sin CASE en cada consulta.
    severity_rank = Column(SmallInteger, nullable=False, default=0, index=True)
    cvss_score = Column(Numeric(4, 1), index=True)
    cvss_version = Column(String)
    description = Column(Text)
    reference = Column(Text)
    published_at = Column(DateTime(timezone=True), nullable=True)

    findings = relationship("VulnerabilityFinding", back_populates="catalog_entry")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical','High','Medium','Low','Unknown')",
            name="ck_catalog_severity",
        ),
        CheckConstraint(
            "severity_rank BETWEEN 0 AND 4", name="ck_catalog_severity_rank"
        ),
    )


# ---------------------------------------------------------------------------
# Inventario
# ---------------------------------------------------------------------------
class Asset(Base):
    """Agente/servidor monitoreado. Un asset pertenece a una sola conexión."""

    __tablename__ = "assets"

    id = Column(BigIntPk, primary_key=True, autoincrement=True)
    connection_id = Column(
        Integer,
        ForeignKey("wazuh_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    wazuh_agent_id = Column(String, nullable=False)
    hostname = Column(String, index=True)
    ip_address = Column(String(45).with_variant(INET, "postgresql"))
    os_id = Column(Integer, ForeignKey("operating_systems.id"), nullable=True, index=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    connection = relationship("WazuhConnection", back_populates="assets")
    operating_system = relationship("OperatingSystem")
    group_members = relationship(
        "AssetGroupMember", back_populates="asset", cascade="all, delete-orphan"
    )
    findings = relationship(
        "VulnerabilityFinding", back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "connection_id", "wazuh_agent_id", name="uq_asset_connection_agent"
        ),
    )


class AssetGroupMember(Base):
    """Relación N:M asset <-> grupo (un agente Wazuh puede estar en varios)."""

    __tablename__ = "asset_group_members"

    asset_id = Column(
        BigIntPk, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    group_id = Column(
        Integer, ForeignKey("agent_groups.id", ondelete="CASCADE"), primary_key=True
    )

    asset = relationship("Asset", back_populates="group_members")
    group = relationship("AgentGroup", back_populates="members")


# ---------------------------------------------------------------------------
# Hechos
# ---------------------------------------------------------------------------
class VulnerabilityFinding(Base):
    """Estado ACTUAL de una vulnerabilidad en un asset para un paquete.

    Reemplaza a ``wazuh_vulnerabilities``: la identidad del hallazgo es
    (asset, CVE, paquete) mediante claves foráneas, sin repetir los textos.
    """

    __tablename__ = "vulnerability_findings"

    id = Column(BigIntPk, primary_key=True, autoincrement=True)
    asset_id = Column(
        BigIntPk, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cve_id = Column(
        String, ForeignKey("vulnerability_catalog.cve_id"), nullable=False, index=True
    )
    package_id = Column(
        BigIntPk, ForeignKey("packages.id"), nullable=False, index=True
    )

    status = Column(String, nullable=False, default="ACTIVE")
    score_base = Column(Numeric(4, 1))
    score_version = Column(String)
    scanner_vendor = Column(String)

    detected_at = Column(DateTime(timezone=True), nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    asset = relationship("Asset", back_populates="findings")
    catalog_entry = relationship("VulnerabilityCatalog", back_populates="findings")
    package = relationship("Package", back_populates="findings")
    history = relationship(
        "FindingHistory", back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "cve_id", "package_id", name="uq_finding_identity"
        ),
        CheckConstraint("status IN ('ACTIVE','RESOLVED')", name="ck_finding_status"),
        Index("idx_finding_asset_status", "asset_id", "status"),
        Index("idx_finding_status_first_seen", "status", "first_seen"),
        Index("idx_finding_last_seen", "last_seen"),
    )


class FindingHistory(Base):
    """Bitácora de cambios de un hallazgo (DETECTED/REOPENED/RESOLVED/...)."""

    __tablename__ = "finding_history"

    id = Column(BigIntPk, primary_key=True, autoincrement=True)
    finding_id = Column(
        BigIntPk,
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    finding = relationship("VulnerabilityFinding", back_populates="history")


class VulnerabilityDetection(Base):
    """Evento en el tiempo (hypertable TimescaleDB particionada por timestamp).

    Solo guarda QUÉ pasó y CUÁNDO; el resto se navega por ``finding_id``.
    """

    __tablename__ = "vulnerability_detections"

    timestamp = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    finding_id = Column(
        BigIntPk,
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    status = Column(String, nullable=False)

    finding = relationship("VulnerabilityFinding")

    __table_args__ = (
        CheckConstraint(
            "status IN ('Detected','Re-emerged','Resolved')",
            name="ck_detection_status",
        ),
        Index("idx_detection_finding_time", "finding_id", "timestamp"),
        Index("idx_detection_status_time", "status", "timestamp"),
    )


def severity_rank(severity: str) -> int:
    """Puntaje numérico de criticidad usado para filtrar y ordenar."""
    return SEVERITY_RANKS.get(severity, 0)
