# app/wazuh_client.py
import base64
import requests

VULN_INDEX = "wazuh-states-vulnerabilities-*/_search"
BATCH_SIZE = 10_000


def _basic_auth_header(user: str, password: str) -> dict:
    """Genera el header Authorization con UTF-8 para soportar caracteres como ñ."""
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    """Trae TODAS las vulnerabilidades usando search_after (sin límite de 10k)."""
    url = f"{indexer_url}/{VULN_INDEX}"
    headers = _basic_auth_header(wazuh_user, wazuh_password)
    all_sources = []
    search_after = None

    while True:
        body = {
            "size": BATCH_SIZE,
            "_source": True,
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": "asc"}
            ]
        }
        if search_after:
            body["search_after"] = search_after

        resp = requests.post(
            url,
            json=body,
            headers=headers,
            verify=False,
            timeout=120
        )
        resp.raise_for_status()

        hits = resp.json()["hits"]["hits"]
        if not hits:
            break

        all_sources.extend(h["_source"] for h in hits)
        print(f"[wazuh_client] Descargadas {len(all_sources)} vulnerabilidades...")

        if len(hits) < BATCH_SIZE:
            break

        search_after = hits[-1]["sort"]

    print(f"[wazuh_client] Total descargado: {len(all_sources)}")
    return all_sources


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    try:
        resp = requests.get(
            indexer_url,
            headers=_basic_auth_header(wazuh_user, wazuh_password),
            verify=False,
            timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[wazuh_client] test_connection error: {e}")
        return False