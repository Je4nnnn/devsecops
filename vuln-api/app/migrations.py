# app/migrations.py
"""Migraciones versionadas del esquema.

Se ejecutan solas al arrancar la API y se registran en ``schema_migrations``,
de modo que cada una corre UNA sola vez por base de datos.

Hay dos fases porque SQLAlchemy no altera tablas ya existentes:

``PRE``   se ejecuta ANTES de ``Base.metadata.create_all``. Aquí se aparta el
          esquema antiguo renombrando sus tablas a ``legacy_*`` para que
          ``create_all`` pueda crear las nuevas limpias. **No se borra nada**:
          las tablas ``legacy_*`` quedan como respaldo.

``POST``  se ejecuta DESPUÉS de ``create_all``, cuando las tablas nuevas ya
          existen, y copia los datos del esquema antiguo al nuevo.

Solo aplica en PostgreSQL; en SQLite (pruebas) no hay nada que migrar.
"""

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

PRE = "pre"
POST = "post"

# Tablas del modelo antiguo que se apartan como respaldo antes de crear el nuevo.
_LEGACY_RENAMES = [
    "managers",
    "assets",
    "vulnerability_catalog",
    "vulnerability_detections",
    "wazuh_vulnerabilities",
    "vulnerability_history",
]

# Normalización de severidad usada en toda la migración.
_SEVERITY_EXPR = """
    CASE lower(coalesce({col}, ''))
        WHEN 'critical' THEN 'Critical' WHEN 'critica' THEN 'Critical'
        WHEN 'crítica'  THEN 'Critical'
        WHEN 'high'     THEN 'High'     WHEN 'alta'    THEN 'High'
        WHEN 'medium'   THEN 'Medium'   WHEN 'media'   THEN 'Medium'
        WHEN 'low'      THEN 'Low'      WHEN 'baja'    THEN 'Low'
        ELSE 'Unknown'
    END
"""

_SEVERITY_RANK_EXPR = """
    CASE lower(coalesce({col}, ''))
        WHEN 'critical' THEN 4 WHEN 'critica' THEN 4 WHEN 'crítica' THEN 4
        WHEN 'high'     THEN 3 WHEN 'alta'    THEN 3
        WHEN 'medium'   THEN 2 WHEN 'media'   THEN 2
        WHEN 'low'      THEN 1 WHEN 'baja'    THEN 1
        ELSE 0
    END
"""


def _table_exists(conn, name: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT to_regclass(:qualified) IS NOT NULL"),
            {"qualified": f"public.{name}"},
        ).scalar()
    )


def _column_exists(conn, table: str, column: str) -> bool:
    return bool(
        conn.execute(
            text(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = :table
                  AND column_name = :column
                """
            ),
            {"table": table, "column": column},
        ).first()
    )


# ---------------------------------------------------------------------------
# 001 · PRE — apartar el esquema antiguo
# ---------------------------------------------------------------------------
def _m001_rename_legacy(conn) -> None:
    """Renombra el modelo antiguo a ``legacy_*`` (respaldo, no destructivo).

    Se reconoce el modelo antiguo porque ``assets`` tenía ``manager_id``: ese
    era el puente confuso entre ``managers`` y ``wazuh_connections``.
    """
    is_legacy = _table_exists(conn, "assets") and _column_exists(
        conn, "assets", "manager_id"
    )
    if not is_legacy:
        return

    for table in _LEGACY_RENAMES:
        if _table_exists(conn, table) and not _table_exists(conn, f"legacy_{table}"):
            conn.execute(text(f'ALTER TABLE "{table}" RENAME TO "legacy_{table}"'))

    # Los procedimientos del modelo antiguo apuntan a tablas que ya no existen.
    for fn in (
        "sp_traceability_timeline(INTEGER, INTERVAL, TIMESTAMPTZ, TIMESTAMPTZ)",
        "sp_traceability_summary(INTEGER, INTERVAL)",
    ):
        conn.execute(text(f"DROP FUNCTION IF EXISTS {fn}"))


# ---------------------------------------------------------------------------
# 002 · POST — copiar los datos al modelo nuevo
# ---------------------------------------------------------------------------
def _m002_migrate_data(conn) -> None:
    if not _table_exists(conn, "legacy_wazuh_vulnerabilities"):
        return
    if conn.execute(text("SELECT 1 FROM vulnerability_findings LIMIT 1")).first():
        return  # ya hay datos nuevos: no se sobrescribe nada

    sev = _SEVERITY_EXPR.format(col="lw.severity")
    rank = _SEVERITY_RANK_EXPR.format(col="lw.severity")

    # --- Dimensión: sistemas operativos ---
    # OJO: "full" es palabra reservada en PostgreSQL (FULL JOIN) y debe ir
    # entre comillas dobles siempre que aparezca sin calificar.
    conn.execute(text("""
        INSERT INTO operating_systems (platform, version, "full", name)
        SELECT DISTINCT
            coalesce(lw.os_platform, ''), coalesce(lw.os_version, ''),
            coalesce(lw.os_full, ''),     coalesce(lw.os_platform, '')
        FROM legacy_wazuh_vulnerabilities lw
        ON CONFLICT ON CONSTRAINT uq_os_identity DO NOTHING
    """))

    # --- Dimensión: paquetes ---
    conn.execute(text("""
        INSERT INTO packages (name, version, type, architecture)
        SELECT DISTINCT
            coalesce(lw.package_name, ''),  coalesce(lw.package_version, ''),
            coalesce(lw.package_type, ''),  coalesce(lw.package_arch, '')
        FROM legacy_wazuh_vulnerabilities lw
        ON CONFLICT ON CONSTRAINT uq_package_identity DO NOTHING
    """))

    # --- Dimensión: catálogo de CVEs (criticidad autoritativa) ---
    conn.execute(text(f"""
        INSERT INTO vulnerability_catalog
            (cve_id, severity, severity_rank, cvss_score, cvss_version,
             description, reference, published_at)
        SELECT DISTINCT ON (lw.cve_id)
            lw.cve_id, {sev}, {rank}, lw.score_base, lw.score_version,
            lw.description, lw.reference, lw.published_at
        FROM legacy_wazuh_vulnerabilities lw
        WHERE lw.cve_id IS NOT NULL
        ORDER BY lw.cve_id, {rank} DESC, lw.score_base DESC NULLS LAST
        ON CONFLICT (cve_id) DO NOTHING
    """))

    # --- Inventario: assets (hostname/IP/S.O. del registro más reciente) ---
    conn.execute(text("""
        INSERT INTO assets
            (connection_id, wazuh_agent_id, hostname, ip_address, os_id,
             first_seen, last_seen)
        SELECT DISTINCT ON (lw.connection_id, lw.agent_id)
            lw.connection_id,
            lw.agent_id,
            lw.agent_name,
            la.ip_address,
            os.id,
            min(lw.first_seen) OVER (PARTITION BY lw.connection_id, lw.agent_id),
            max(lw.last_seen)  OVER (PARTITION BY lw.connection_id, lw.agent_id)
        FROM legacy_wazuh_vulnerabilities lw
        LEFT JOIN operating_systems os
               ON os.platform = coalesce(lw.os_platform, '')
              AND os.version  = coalesce(lw.os_version, '')
              AND os."full"   = coalesce(lw.os_full, '')
        LEFT JOIN legacy_managers lm ON lm.legacy_connection_id = lw.connection_id
        LEFT JOIN legacy_assets la
               ON la.manager_id = lm.id AND la.wazuh_agent_id = lw.agent_id
        WHERE lw.agent_id IS NOT NULL
        ORDER BY lw.connection_id, lw.agent_id, lw.last_seen DESC
        ON CONFLICT ON CONSTRAINT uq_asset_connection_agent DO NOTHING
    """))

    # --- Hechos: hallazgos, conservando el id antiguo para remapear ---
    conn.execute(text("""
        CREATE TEMP TABLE finding_id_map (legacy_id BIGINT PRIMARY KEY, new_id BIGINT)
        ON COMMIT DROP
    """))
    conn.execute(text("""
        WITH inserted AS (
            INSERT INTO vulnerability_findings
                (asset_id, cve_id, package_id, status, score_base, score_version,
                 scanner_vendor, detected_at, first_seen, last_seen, resolved_at)
            SELECT DISTINCT ON (a.id, lw.cve_id, p.id)
                a.id, lw.cve_id, p.id,
                CASE WHEN upper(coalesce(lw.status, 'ACTIVE')) = 'RESOLVED'
                     THEN 'RESOLVED' ELSE 'ACTIVE' END,
                lw.score_base, lw.score_version, lw.scanner_vendor,
                lw.detected_at, lw.first_seen, lw.last_seen,
                CASE WHEN upper(coalesce(lw.status, 'ACTIVE')) = 'RESOLVED'
                     THEN lw.last_seen END
            FROM legacy_wazuh_vulnerabilities lw
            JOIN assets a
              ON a.connection_id = lw.connection_id
             AND a.wazuh_agent_id = lw.agent_id
            JOIN packages p
              ON p.name = coalesce(lw.package_name, '')
             AND p.version = coalesce(lw.package_version, '')
             AND p.type = coalesce(lw.package_type, '')
             AND p.architecture = coalesce(lw.package_arch, '')
            JOIN vulnerability_catalog vc ON vc.cve_id = lw.cve_id
            ORDER BY a.id, lw.cve_id, p.id, lw.last_seen DESC
            RETURNING id, asset_id, cve_id, package_id
        )
        INSERT INTO finding_id_map (legacy_id, new_id)
        SELECT DISTINCT ON (lw.id) lw.id, i.id
        FROM legacy_wazuh_vulnerabilities lw
        JOIN assets a
          ON a.connection_id = lw.connection_id AND a.wazuh_agent_id = lw.agent_id
        JOIN packages p
          ON p.name = coalesce(lw.package_name, '')
         AND p.version = coalesce(lw.package_version, '')
         AND p.type = coalesce(lw.package_type, '')
         AND p.architecture = coalesce(lw.package_arch, '')
        JOIN inserted i
          ON i.asset_id = a.id AND i.cve_id = lw.cve_id AND i.package_id = p.id
        ON CONFLICT (legacy_id) DO NOTHING
    """))

    # --- Bitácora de cambios ---
    if _table_exists(conn, "legacy_vulnerability_history"):
        conn.execute(text("""
            INSERT INTO finding_history (finding_id, action, details, timestamp)
            SELECT m.new_id, lh.action, lh.details, lh.timestamp
            FROM legacy_vulnerability_history lh
            JOIN finding_id_map m ON m.legacy_id = lh.vulnerability_id
        """))

    # --- Eventos: se remapean por (asset, CVE, paquete) ---
    if _table_exists(conn, "legacy_vulnerability_detections"):
        conn.execute(text("""
            INSERT INTO vulnerability_detections (timestamp, finding_id, status)
            SELECT DISTINCT ON (f.id, ld.timestamp) ld.timestamp, f.id, ld.status::text
            FROM legacy_vulnerability_detections ld
            JOIN legacy_assets la   ON la.id = ld.asset_id
            JOIN legacy_managers lm ON lm.id = la.manager_id
            JOIN assets a
              ON a.connection_id = lm.legacy_connection_id
             AND a.wazuh_agent_id = la.wazuh_agent_id
            JOIN packages p
              ON p.name = coalesce(ld.package_name, '')
             AND p.version = coalesce(ld.package_version, '')
            JOIN vulnerability_findings f
              ON f.asset_id = a.id AND f.cve_id = ld.cve_id AND f.package_id = p.id
            ORDER BY f.id, ld.timestamp
            ON CONFLICT DO NOTHING
        """))

    # Secuencias al día tras los INSERT con id explícito/implícito.
    for table in ("assets", "packages", "vulnerability_findings", "finding_history"):
        conn.execute(
            text(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'),"
                f" coalesce((SELECT max(id) FROM {table}), 1))"
            )
        )


MIGRATIONS = [
    ("001_rename_legacy_schema", PRE, _m001_rename_legacy),
    ("002_migrate_legacy_data", POST, _m002_migrate_data),
]


def _ensure_registry(conn) -> None:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version     TEXT PRIMARY KEY,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))


def _applied(conn) -> set:
    return {row[0] for row in conn.execute(text("SELECT version FROM schema_migrations"))}


def run_migrations(engine, phase: str) -> None:
    """Aplica las migraciones pendientes de la fase indicada."""
    if engine.dialect.name != "postgresql":
        return

    try:
        with engine.begin() as conn:
            _ensure_registry(conn)
            done = _applied(conn)

        for version, mig_phase, fn in MIGRATIONS:
            if mig_phase != phase or version in done:
                continue
            with engine.begin() as conn:
                fn(conn)
                conn.execute(
                    text("INSERT INTO schema_migrations (version) VALUES (:v)"),
                    {"v": version},
                )
            print(f"[migrations] aplicada {version}")
    except SQLAlchemyError as exc:
        print(f"[migrations] error aplicando migraciones ({phase}): {exc}")
        raise
