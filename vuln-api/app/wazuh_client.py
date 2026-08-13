# app/wazuh_client.py
import base64
import os

import requests

VULN_INDEX = "wazuh-states-vulnerabilities-*/_search"
MONITORING_INDEX = "wazuh-monitoring-*/_search"
BATCH_SIZE = 10_000


def _tls_verification():
    value = os.getenv("WAZUH_VERIFY_TLS", "true").strip()
    normalized = value.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return value


def _basic_auth_header(user: str, password: str) -> dict:
    """Genera el header Authorization con UTF-8 para soportar caracteres como ñ."""
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


class WazuhVulnerabilityStream:
    """Iterador paginado que mantiene como maximo un lote de Wazuh en memoria."""

    def __init__(self, indexer_url: str, wazuh_user: str, wazuh_password: str):
        self.url = f"{indexer_url.rstrip('/')}/{VULN_INDEX}"
        self.group_url = f"{indexer_url.rstrip('/')}/{MONITORING_INDEX}"
        self.headers = _basic_auth_header(wazuh_user, wazuh_password)
        self.batch_size = int(os.getenv("WAZUH_BATCH_SIZE", str(BATCH_SIZE)))
        self.timeout = int(os.getenv("WAZUH_REQUEST_TIMEOUT", "120"))
        self._first_hits = None
        self._primed = False
        self._total = None
        self._consumed = False

        self._agent_groups_loaded = False
        self._agent_groups = None
    def _request(self, search_after=None):

        body = {
            "size": self.batch_size,
            "_source": True,
            "track_total_hits": True,
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": "asc"}
            ]
        }
        if search_after is not None:
            body["search_after"] = search_after

        resp = requests.post(
            self.url,
            json=body,
            headers=self.headers,
            verify=_tls_verification(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json().get("hits") or {}
        return payload, payload.get("hits") or []

    def _prime(self):
        if self._primed:
            return
        payload, hits = self._request()
        raw_total = payload.get("total", len(hits))
        if isinstance(raw_total, dict):
            raw_total = raw_total.get("value", len(hits))
        self._total = int(raw_total)
        self._primed = True
        self._first_hits = hits

    def __len__(self):
        self._prime()
        return self._total

    @property
    def agent_groups(self):
        """Últimos grupos Wazuh por agente, si el índice de monitoreo existe."""
        if not self._agent_groups_loaded:
            self._agent_groups_loaded = True
            try:
                self._agent_groups = fetch_agent_groups(
                    self.group_url,
                    self.headers,
                    batch_size=int(os.getenv("WAZUH_AGENT_LIMIT", "10000")),
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                # Los grupos enriquecen el modelo, pero su ausencia no debe
                # impedir sincronizar vulnerabilidades.
                print(f"[wazuh_client] No se pudieron obtener grupos: {exc}")
                self._agent_groups = None
        return self._agent_groups

    def __iter__(self):
        if self._consumed:
            raise RuntimeError("El flujo Wazuh solo puede recorrerse una vez")
        self._consumed = True
        self._prime()

        hits = self._first_hits
        self._first_hits = None
        downloaded = 0
        while hits:
            for hit in hits:
                yield hit["_source"]

            downloaded += len(hits)
            print(f"[wazuh_client] Descargadas {downloaded}/{self._total} vulnerabilidades...")

            if len(hits) < self.batch_size:
                break

            _, hits = self._request(hits[-1]["sort"])

        print(f"[wazuh_client] Total descargado: {downloaded}")


def fetch_agent_groups(
    url: str, headers: dict, batch_size: int = 10000, timeout: int = 120
):
    """Obtiene el grupo Wazuh más reciente de cada agente desde monitoring."""
    response = requests.post(
        url,
        json={
            "size": max(1, min(batch_size, 10000)),
            "_source": ["id", "name", "group", "timestamp"],
            "query": {"exists": {"field": "group"}},
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "collapse": {"field": "id"},
        },
        headers=headers,
        verify=_tls_verification(),
        timeout=timeout,
    )
    response.raise_for_status()

    result = {}
    for hit in (response.json().get("hits") or {}).get("hits") or []:
        source = hit.get("_source") or {}
        agent_id = source.get("id")
        raw_groups = source.get("group") or []
        if isinstance(raw_groups, str):
            raw_groups = raw_groups.split(",")
        groups = sorted({
            str(group).strip()
            for group in raw_groups
            if str(group).strip()
        })
        if agent_id is not None:
            result[str(agent_id)] = groups
    return result


def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    """Devuelve un flujo Sized/iterable compatible con la ingesta existente."""
    return WazuhVulnerabilityStream(indexer_url, wazuh_user, wazuh_password)


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    try:
        resp = requests.get(
            indexer_url.rstrip("/"),
            headers=_basic_auth_header(wazuh_user, wazuh_password),
            verify=_tls_verification(),
            timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[wazuh_client] test_connection error: {e}")
        return False