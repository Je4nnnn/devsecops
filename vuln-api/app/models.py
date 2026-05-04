# app/models.py
from sqlalchemy import (
    Column,
    Integer,
    Boolean,
    String,
    Text,
    DateTime,
    Numeric,
    Enum as SqlEnum,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .db import Base
import uuid


def new_uuid() -> str:
    return str(uuid.uuid4())


SEVERITY_VALUES = ("Low", "Medium", "High", "Critical")
DETECTION_STATUS_VALUES = ("Detected", "Resolved", "Re-emerged")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=False) 
    is_default_password = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    interactions = relationship("UserInteraction", back_populates="user")


class WazuhConnection(Base):
    __tablename__ = "wazuh_connections"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    indexer_url = Column(String, nullable=False)
    wazuh_user = Column(String, nullable=False)
    wazuh_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    vulnerabilities = relationship("WazuhVulnerability", back_populates="connection")
    tested = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_test_ok = Column(Boolean, nullable=True)


class Manager(Base):
    __tablename__ = "managers"
    id = Column(String(36), primary_key=True, default=new_uuid)
    nombre = Column(String, nullable=False)
    api_url = Column(Text, nullable=False)
    api_key_vault_ref = Column(Text, nullable=False, unique=True)
    legacy_connection_id = Column(Integer, nullable=True, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    assets = relationship("Asset", back_populates="manager", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String(36), primary_key=True, default=new_uuid)
    wazuh_agent_id = Column(String, nullable=False, index=True)
    hostname = Column(String)
    os_version = Column(String)
    ip_address = Column(String(45).with_variant(INET, "postgresql"))
    manager_id = Column(String(36), ForeignKey("managers.id"), nullable=False, index=True)
    manager = relationship("Manager", back_populates="assets")
    detections = relationship("VulnerabilityDetection", back_populates="asset")
    __table_args__ = (
        UniqueConstraint("manager_id", "wazuh_agent_id", name="uniq_asset_manager_agent"),
    )


class VulnerabilityCatalog(Base):
    __tablename__ = "vulnerability_catalog"
    cve_id = Column(String, primary_key=True)
    severity = Column(
        SqlEnum(*SEVERITY_VALUES, name="severity_enum", native_enum=True),
        nullable=False,
        default="Low",
    )
    description = Column(Text)
    cvss_score = Column(Numeric(3, 1))
    detections = relationship("VulnerabilityDetection", back_populates="catalog_entry")


class VulnerabilityDetection(Base):
    __tablename__ = "vulnerability_detections"
    event_id = Column(String(36), primary_key=True, default=new_uuid)
    timestamp = Column(DateTime(timezone=True), primary_key=True, index=True, nullable=False)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    cve_id = Column(String, ForeignKey("vulnerability_catalog.cve_id"), nullable=False, index=True)
    status = Column(
        SqlEnum(*DETECTION_STATUS_VALUES, name="detection_status_enum", native_enum=True),
        nullable=False,
        index=True,
    )
    package_name = Column(String, nullable=False, default="")
    package_version = Column(String, nullable=False, default="")
    asset = relationship("Asset", back_populates="detections")
    catalog_entry = relationship("VulnerabilityCatalog", back_populates="detections")


class UserInteraction(Base):
    __tablename__ = "user_interactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    endpoint = Column(String, index=True)
    method = Column(String)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="interactions")


class WazuhVulnerability(Base):
    __tablename__ = "wazuh_vulnerabilities"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    connection_id = Column(Integer, ForeignKey("wazuh_connections.id"), nullable=False)
    connection = relationship("WazuhConnection", back_populates="vulnerabilities")
    status = Column(String, default="ACTIVE")
    agent_id = Column(String, nullable=False, index=True)
    agent_name = Column(String)
    os_full = Column(Text)
    os_platform = Column(Text)
    os_version = Column(Text)
    package_name = Column(Text)
    package_version = Column(Text)
    package_type = Column(Text)
    package_arch = Column(Text)
    cve_id = Column(Text, nullable=False)
    severity = Column(Text)
    score_base = Column(Numeric)
    score_version = Column(Text)
    detected_at = Column(DateTime(timezone=True))
    published_at = Column(DateTime(timezone=True))
    description = Column(Text)
    reference = Column(Text)
    scanner_vendor = Column(Text)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    history = relationship(
        "VulnerabilityHistory",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    __table_args__ = (
        UniqueConstraint(
            "connection_id",
            "agent_id",
            "package_name",
            "package_version",
            "cve_id",
            name="uniq_wazuh_vuln",
        ),
    )


class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("wazuh_vulnerabilities.id"), nullable=False
    )
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    vulnerability = relationship("WazuhVulnerability", back_populates="history")
