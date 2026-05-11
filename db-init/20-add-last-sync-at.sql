-- Migración: agrega last_sync_at a wazuh_connections
-- Ejecutar UNA SOLA VEZ en BD existente:
--   docker compose exec db-api psql -U admin -d vulnerabilidades_db -f /docker-entrypoint-initdb.d/20-add-last-sync-at.sql

ALTER TABLE wazuh_connections
  ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ DEFAULT NULL;
