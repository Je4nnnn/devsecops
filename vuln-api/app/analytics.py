# app/analytics.py
"""Objetos analíticos en PostgreSQL: hypertable, índices y procedimientos.

Toda la agregación pesada vive en la base de datos. El frontend solo consume
resultados ya calculados, sin descargar el dataset.

Endurecimiento aplicado a TODOS los procedimientos (revisión de seguridad):

1. ``SECURITY INVOKER`` — la función corre con los privilegios de quien la
   llama, no del dueño. Sin escalada de privilegios.
2. ``SET search_path = pg_catalog, public`` — fija el search_path en la
   definición. Impide el secuestro por un esquema temporal del atacante
   (CVE-2018-1058 y familia).
3. ``LANGUAGE sql`` + parámetros tipados — no hay SQL dinámico ni
   concatenación de strings, así que no hay superficie de inyección. Los
   parámetros de texto que podrían llegar a una función del sistema
   (``date_trunc``) se validan contra una lista blanca dentro de la propia
   función.
4. ``STABLE`` — declaradas de solo lectura; no pueden escribir.
5. ``REVOKE ALL ... FROM PUBLIC`` + ``GRANT EXECUTE`` explícito — nadie más
   que el rol de la aplicación puede ejecutarlas.
6. Sin ``SELECT *`` y sin devolver credenciales: ninguna función toca
   ``wazuh_connections.wazuh_password`` ni ``users.password_hash``.
"""

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Unidades permitidas para date_trunc (lista blanca aplicada en SQL).
BUCKET_UNITS = ("hour", "day", "week", "month", "quarter", "year")

_INDEXES = [
    # Filtros server-side sobre el hecho principal
    "CREATE INDEX IF NOT EXISTS idx_finding_cve ON vulnerability_findings (cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_finding_package ON vulnerability_findings (package_id)",
    "CREATE INDEX IF NOT EXISTS idx_finding_score ON vulnerability_findings (score_base)",
    "CREATE INDEX IF NOT EXISTS idx_finding_resolved_at ON vulnerability_findings (resolved_at)",
    "CREATE INDEX IF NOT EXISTS idx_finding_status_asset ON vulnerability_findings (status, asset_id)",
    # Inventario
    "CREATE INDEX IF NOT EXISTS idx_asset_conn_host ON assets (connection_id, hostname)",
    "CREATE INDEX IF NOT EXISTS idx_agm_group ON asset_group_members (group_id)",
    # Dimensiones
    "CREATE INDEX IF NOT EXISTS idx_catalog_rank_score ON vulnerability_catalog (severity_rank DESC, cvss_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_package_name_version ON packages (name, version)",
]

# Base común de joins reutilizada por los procedimientos.
_FINDING_JOINS = """
    FROM vulnerability_findings f
    JOIN assets a                ON a.id = f.asset_id
    JOIN vulnerability_catalog c ON c.cve_id = f.cve_id
"""

# ---------------------------------------------------------------------------
# Definición de los procedimientos almacenados
#   (signatura_para_grant, cuerpo_completo)
# ---------------------------------------------------------------------------
_PROCEDURES = [
    # -- Filtros grandes: se resuelven en BD para no traer 20k filas a la UI --
    (
        "sp_filter_groups(INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_filter_groups(p_connection_id INTEGER)
        RETURNS TABLE(group_id INTEGER, name TEXT, assets BIGINT, activas BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT g.id,
                   g.name::text,
                   count(DISTINCT a.id),
                   count(*) FILTER (WHERE f.status = 'ACTIVE')
            FROM agent_groups g
            JOIN asset_group_members m ON m.group_id = g.id
            JOIN assets a              ON a.id = m.asset_id
            LEFT JOIN vulnerability_findings f ON f.asset_id = a.id
            WHERE (p_connection_id IS NULL OR g.connection_id = p_connection_id)
            GROUP BY g.id, g.name
            ORDER BY g.name
        $$;
        """,
    ),
    (
        "sp_filter_operating_systems(INTEGER)",
        """
        CREATE OR REPLACE FUNCTION sp_filter_operating_systems(p_connection_id INTEGER)
        RETURNS TABLE(os_id INTEGER, platform TEXT, version TEXT, full_name TEXT, assets BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT o.id, o.platform::text, o.version::text, o."full"::text, count(a.id)
            FROM operating_systems o
            JOIN assets a ON a.os_id = o.id
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            GROUP BY o.id, o.platform, o.version, o."full"
            ORDER BY o.platform, o.version
        $$;
        """,
    ),
    (
        "sp_filter_severities(INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_filter_severities(p_connection_id INTEGER)
        RETURNS TABLE(severity TEXT, severity_rank SMALLINT, total BIGINT,
                      score_min NUMERIC, score_max NUMERIC)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT c.severity::text, c.severity_rank, count(*),
                   min(f.score_base), max(f.score_base)
            {_FINDING_JOINS}
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            GROUP BY c.severity, c.severity_rank
            ORDER BY c.severity_rank DESC
        $$;
        """,
    ),
    (
        "sp_filter_agents(INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_filter_agents(p_connection_id INTEGER)
        RETURNS TABLE(asset_id BIGINT, hostname TEXT, wazuh_agent_id TEXT, total BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT a.id, a.hostname::text, a.wazuh_agent_id::text,
                   count(f.id) FILTER (WHERE f.status = 'ACTIVE')
            FROM assets a
            LEFT JOIN vulnerability_findings f ON f.asset_id = a.id
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            GROUP BY a.id, a.hostname, a.wazuh_agent_id
            ORDER BY a.hostname
        $$;
        """,
    ),
    (
        "sp_filter_packages(INTEGER, TEXT, INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_filter_packages(
            p_connection_id INTEGER,
            p_search        TEXT DEFAULT NULL,
            p_limit         INTEGER DEFAULT 500
        )
        RETURNS TABLE(name TEXT, versions BIGINT, afectados BIGINT, activas BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT p.name::text,
                   count(DISTINCT p.version),
                   count(DISTINCT f.asset_id),
                   count(*) FILTER (WHERE f.status = 'ACTIVE')
            FROM packages p
            JOIN vulnerability_findings f ON f.package_id = p.id
            JOIN assets a ON a.id = f.asset_id
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
              AND (p_search IS NULL OR p.name ILIKE '%' || p_search || '%')
            GROUP BY p.name
            ORDER BY count(*) FILTER (WHERE f.status = 'ACTIVE') DESC, p.name
            LIMIT greatest(1, least(coalesce(p_limit, 500), 5000))
        $$;
        """,
    ),
    (
        "sp_filter_cves(INTEGER, TEXT, INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_filter_cves(
            p_connection_id INTEGER,
            p_search        TEXT DEFAULT NULL,
            p_limit         INTEGER DEFAULT 1000
        )
        RETURNS TABLE(cve_id TEXT, severity TEXT, cvss_score NUMERIC, total BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT c.cve_id::text, c.severity::text, c.cvss_score, count(*)
            {_FINDING_JOINS}
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
              AND (p_search IS NULL OR c.cve_id ILIKE '%' || p_search || '%')
            GROUP BY c.cve_id, c.severity, c.cvss_score
            ORDER BY c.severity_rank DESC, c.cve_id
            LIMIT greatest(1, least(coalesce(p_limit, 1000), 10000))
        $$;
        """,
    ),
    # -- Inventario de paquetes (tabla paquetes de la entrega) --
    (
        "sp_package_inventory(INTEGER, TEXT, INTEGER, INTEGER, INTEGER)",
        """
        CREATE OR REPLACE FUNCTION sp_package_inventory(
            p_connection_id INTEGER,
            p_search        TEXT DEFAULT NULL,
            p_min_rank      INTEGER DEFAULT 0,
            p_limit         INTEGER DEFAULT 50,
            p_offset        INTEGER DEFAULT 0
        )
        RETURNS TABLE(
            package_id BIGINT, name TEXT, version TEXT, type TEXT, architecture TEXT,
            afectados BIGINT, activas BIGINT, resueltas BIGINT,
            max_score NUMERIC, peor_severidad TEXT, peor_rank SMALLINT
        )
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT p.id, p.name::text, p.version::text, p.type::text,
                   p.architecture::text,
                   count(DISTINCT f.asset_id),
                   count(*) FILTER (WHERE f.status = 'ACTIVE'),
                   count(*) FILTER (WHERE f.status = 'RESOLVED'),
                   max(c.cvss_score),
                   (array_agg(c.severity ORDER BY c.severity_rank DESC))[1]::text,
                   max(c.severity_rank)
            FROM packages p
            JOIN vulnerability_findings f ON f.package_id = p.id
            JOIN assets a                ON a.id = f.asset_id
            JOIN vulnerability_catalog c ON c.cve_id = f.cve_id
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
              AND (p_search IS NULL OR p.name ILIKE '%' || p_search || '%')
              AND c.severity_rank >= coalesce(p_min_rank, 0)
            GROUP BY p.id, p.name, p.version, p.type, p.architecture
            ORDER BY max(c.severity_rank) DESC, count(*) FILTER (WHERE f.status = 'ACTIVE') DESC,
                     p.name, p.version
            LIMIT greatest(1, least(coalesce(p_limit, 50), 500))
            OFFSET greatest(0, coalesce(p_offset, 0))
        $$;
        """,
    ),
    # -- Trazabilidad temporal (periodos en MESES por defecto) --
    (
        "sp_traceability_timeline(INTEGER, TEXT, TIMESTAMPTZ, TIMESTAMPTZ)",
        """
        CREATE OR REPLACE FUNCTION sp_traceability_timeline(
            p_connection_id INTEGER,
            p_unit          TEXT,
            p_start         TIMESTAMPTZ,
            p_end           TIMESTAMPTZ
        )
        RETURNS TABLE(bucket TIMESTAMPTZ, nuevas BIGINT, reemergidas BIGINT, remediadas BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT date_trunc(
                       CASE WHEN p_unit IN ('hour','day','week','month','quarter','year')
                            THEN p_unit ELSE 'month' END,
                       d.timestamp
                   ) AS bucket,
                   count(*) FILTER (WHERE d.status = 'Detected'),
                   count(*) FILTER (WHERE d.status = 'Re-emerged'),
                   count(*) FILTER (WHERE d.status = 'Resolved')
            FROM vulnerability_detections d
            JOIN vulnerability_findings f ON f.id = d.finding_id
            JOIN assets a                ON a.id = f.asset_id
            WHERE d.timestamp >= p_start
              AND d.timestamp <= p_end
              AND (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            GROUP BY 1
            ORDER BY 1
        $$;
        """,
    ),
    (
        "sp_traceability_summary(INTEGER, INTERVAL)",
        f"""
        CREATE OR REPLACE FUNCTION sp_traceability_summary(
            p_connection_id INTEGER,
            p_new_window    INTERVAL DEFAULT INTERVAL '1 month'
        )
        RETURNS TABLE(nuevas BIGINT, persistentes BIGINT, remediadas BIGINT, total_activas BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT
                count(*) FILTER (WHERE f.status = 'ACTIVE'
                                   AND f.first_seen >= now() - p_new_window),
                count(*) FILTER (WHERE f.status = 'ACTIVE'
                                   AND f.first_seen <  now() - p_new_window),
                count(*) FILTER (WHERE f.status = 'RESOLVED'),
                count(*) FILTER (WHERE f.status = 'ACTIVE')
            {_FINDING_JOINS}
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
        $$;
        """,
    ),
    # -- Dashboard: torta resueltas vs activas --
    (
        "sp_status_breakdown(INTEGER, INTEGER, INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_status_breakdown(
            p_connection_id INTEGER,
            p_group_id      INTEGER DEFAULT NULL,
            p_min_rank      INTEGER DEFAULT 0
        )
        RETURNS TABLE(activas BIGINT, resueltas BIGINT, total BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT count(*) FILTER (WHERE f.status = 'ACTIVE'),
                   count(*) FILTER (WHERE f.status = 'RESOLVED'),
                   count(*)
            {_FINDING_JOINS}
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
              AND c.severity_rank >= coalesce(p_min_rank, 0)
              AND (p_group_id IS NULL OR EXISTS (
                    SELECT 1 FROM asset_group_members m
                    WHERE m.asset_id = a.id AND m.group_id = p_group_id))
        $$;
        """,
    ),
    # -- Dashboard: % de vulnerabilidades nuevas del año que siguen sin corregir --
    (
        "sp_new_unresolved_ratio(INTEGER, INTEGER)",
        f"""
        CREATE OR REPLACE FUNCTION sp_new_unresolved_ratio(
            p_connection_id INTEGER,
            p_year          INTEGER
        )
        RETURNS TABLE(anio INTEGER, nuevas BIGINT, sin_corregir BIGINT,
                      corregidas BIGINT, pct_sin_corregir NUMERIC)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT p_year,
                   count(*),
                   count(*) FILTER (WHERE f.status = 'ACTIVE'),
                   count(*) FILTER (WHERE f.status = 'RESOLVED'),
                   round(
                       100.0 * count(*) FILTER (WHERE f.status = 'ACTIVE')
                       / nullif(count(*), 0), 1)
            {_FINDING_JOINS}
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
              AND extract(YEAR FROM f.first_seen) = p_year
        $$;
        """,
    ),
    # -- Dashboard: % de agentes y grupos con al menos una vulnerabilidad crítica --
    (
        "sp_critical_coverage(INTEGER, INTEGER)",
        """
        CREATE OR REPLACE FUNCTION sp_critical_coverage(
            p_connection_id INTEGER,
            p_min_rank      INTEGER DEFAULT 4
        )
        RETURNS TABLE(
            total_agentes BIGINT, agentes_criticos BIGINT, pct_agentes NUMERIC,
            total_grupos BIGINT,  grupos_criticos BIGINT,  pct_grupos NUMERIC
        )
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            WITH criticos AS (
                SELECT DISTINCT f.asset_id
                FROM vulnerability_findings f
                JOIN vulnerability_catalog c ON c.cve_id = f.cve_id
                WHERE f.status = 'ACTIVE'
                  AND c.severity_rank >= coalesce(p_min_rank, 4)
            ),
            ag AS (
                SELECT a.id, (cr.asset_id IS NOT NULL) AS es_critico
                FROM assets a
                LEFT JOIN criticos cr ON cr.asset_id = a.id
                WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            ),
            gr AS (
                SELECT g.id,
                       bool_or(cr.asset_id IS NOT NULL) AS es_critico
                FROM agent_groups g
                LEFT JOIN asset_group_members m ON m.group_id = g.id
                LEFT JOIN criticos cr ON cr.asset_id = m.asset_id
                WHERE (p_connection_id IS NULL OR g.connection_id = p_connection_id)
                GROUP BY g.id
            )
            SELECT (SELECT count(*) FROM ag),
                   (SELECT count(*) FROM ag WHERE es_critico),
                   (SELECT round(100.0 * count(*) FILTER (WHERE es_critico)
                                 / nullif(count(*), 0), 1) FROM ag),
                   (SELECT count(*) FROM gr),
                   (SELECT count(*) FROM gr WHERE es_critico),
                   (SELECT round(100.0 * count(*) FILTER (WHERE es_critico)
                                 / nullif(count(*), 0), 1) FROM gr)
        $$;
        """,
    ),
    # -- Dashboard: histograma de agentes con al menos N vulnerabilidades críticas --
    (
        "sp_critical_histogram(INTEGER, INTEGER, INTEGER)",
        """
        CREATE OR REPLACE FUNCTION sp_critical_histogram(
            p_connection_id INTEGER,
            p_min_rank      INTEGER DEFAULT 4,
            p_limit         INTEGER DEFAULT 20
        )
        RETURNS TABLE(asset_id BIGINT, hostname TEXT, grupos TEXT,
                      criticas BIGINT, activas BIGINT, max_score NUMERIC)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT a.id,
                   coalesce(a.hostname, a.wazuh_agent_id)::text,
                   coalesce((
                       SELECT string_agg(g.name, ', ' ORDER BY g.name)
                       FROM asset_group_members m
                       JOIN agent_groups g ON g.id = m.group_id
                       WHERE m.asset_id = a.id
                   ), '')::text,
                   count(*) FILTER (WHERE c.severity_rank >= coalesce(p_min_rank, 4)),
                   count(*),
                   max(c.cvss_score)
            FROM assets a
            JOIN vulnerability_findings f ON f.asset_id = a.id AND f.status = 'ACTIVE'
            JOIN vulnerability_catalog c  ON c.cve_id = f.cve_id
            WHERE (p_connection_id IS NULL OR a.connection_id = p_connection_id)
            GROUP BY a.id, a.hostname, a.wazuh_agent_id
            HAVING count(*) FILTER (WHERE c.severity_rank >= coalesce(p_min_rank, 4)) > 0
            ORDER BY 4 DESC, 5 DESC
            LIMIT greatest(1, least(coalesce(p_limit, 20), 200))
        $$;
        """,
    ),
    # -- Dashboard: riesgo agregado por grupo --
    (
        "sp_group_risk(INTEGER, INTEGER, INTEGER)",
        """
        CREATE OR REPLACE FUNCTION sp_group_risk(
            p_connection_id INTEGER,
            p_min_rank      INTEGER DEFAULT 4,
            p_limit         INTEGER DEFAULT 20
        )
        RETURNS TABLE(group_id INTEGER, name TEXT, agentes BIGINT,
                      agentes_criticos BIGINT, criticas BIGINT, activas BIGINT)
        LANGUAGE sql STABLE SECURITY INVOKER
        SET search_path = pg_catalog, public AS $$
            SELECT g.id, g.name::text,
                   count(DISTINCT a.id),
                   count(DISTINCT a.id) FILTER (
                       WHERE c.severity_rank >= coalesce(p_min_rank, 4)),
                   count(f.id) FILTER (
                       WHERE c.severity_rank >= coalesce(p_min_rank, 4)),
                   count(f.id)
            FROM agent_groups g
            JOIN asset_group_members m ON m.group_id = g.id
            JOIN assets a              ON a.id = m.asset_id
            LEFT JOIN vulnerability_findings f
                   ON f.asset_id = a.id AND f.status = 'ACTIVE'
            LEFT JOIN vulnerability_catalog c ON c.cve_id = f.cve_id
            WHERE (p_connection_id IS NULL OR g.connection_id = p_connection_id)
            GROUP BY g.id, g.name
            ORDER BY 5 DESC, 6 DESC
            LIMIT greatest(1, least(coalesce(p_limit, 20), 200))
        $$;
        """,
    ),
]


def initialize_timescale_storage(engine) -> None:
    """Convierte la tabla de eventos en hypertable si TimescaleDB está presente."""
    if engine.dialect.name != "postgresql":
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            conn.execute(text("""
                SELECT create_hypertable(
                    'vulnerability_detections', 'timestamp',
                    if_not_exists => TRUE, migrate_data => TRUE
                )
            """))
    except SQLAlchemyError as exc:
        print(f"TimescaleDB no disponible, se usará PostgreSQL estándar: {exc}")


def initialize_analytics_objects(engine) -> None:
    """Crea índices y procedimientos almacenados endurecidos."""
    if engine.dialect.name != "postgresql":
        return

    try:
        with engine.begin() as conn:
            for statement in _INDEXES:
                conn.execute(text(statement))

            for signature, body in _PROCEDURES:
                conn.execute(text(body))
                # Principio de mínimo privilegio: solo la app puede ejecutarlas.
                conn.execute(text(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC"))
                conn.execute(
                    text(f"GRANT EXECUTE ON FUNCTION {signature} TO CURRENT_USER")
                )
    except SQLAlchemyError as exc:
        print(f"No se pudieron crear objetos analíticos: {exc}")
