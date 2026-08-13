import pytest
from unittest.mock import patch

from app.auth import hash_password
from app.crypto import encrypt
from app.models import (
    AgentGroup,
    Asset,
    AssetGroupMember,
    FindingHistory,
    OperatingSystem,
    Package,
    User,
    VulnerabilityCatalog,
    VulnerabilityDetection,
    VulnerabilityFinding,
    WazuhConnection,
)

# helpers


def _create_user(db, username="admin", password="admin", is_active=True):
    user = User(username=username, password_hash=hash_password(password), is_active=is_active)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _get_headers(client, username="admin", password="admin"):
    res = client.post("/auth/login", data={"username": username, "password": password})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _create_connection(db, name="test-conn", is_active=True):
    conn = WazuhConnection(
        name=name,
        indexer_url="https://wazuh.local:9200",
        wazuh_user="admin",
        wazuh_password=encrypt("secret"),
        is_active=is_active,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn


def _raw_vuln(
    cve="CVE-2023-9999",
    severity="High",
    agent_id="001",
    agent_name="host-1",
    groups=("default",),
    package="curl",
    version="7.81",
    score=6.0,
):
    return [{
        "agent": {"id": agent_id, "name": agent_name, "groups": list(groups)},
        "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
        "package": {"name": package, "version": version, "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": cve, "severity": severity,
            "score": {"base": score, "version": "3.1"},
            "detected_at": None, "published_at": None,
            "description": "desc", "reference": "https://ref",
            "scanner": {"vendor": "wazuh"},
        },
    }]


MOCK_VULN = [
    {
        "agent": {"id": "001", "name": "agent-1", "groups": ["default", "linux"]},
        "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
        "package": {"name": "openssl", "version": "1.1.1", "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": "CVE-2023-0001", "severity": "High",
            "score": {"base": 7.5, "version": "3.1"},
            "detected_at": None, "published_at": None,
            "description": "Test vuln", "reference": "https://nvd.nist.gov",
            "scanner": {"vendor": "wazuh"},
        },
    }
]


# auth


def test_login_fail(client):
    response = client.post("/auth/login", data={"username": "wrong", "password": "password"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Usuario o contraseña incorrectos"


def test_login_inactive_user(client, db_session):
    _create_user(db_session, is_active=False)
    res = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert res.status_code == 400


def test_login_success(client, db_session):
    _create_user(db_session)
    res = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert res.status_code == 200
    assert "access_token" in res.json()


def test_login_unknown_user(client):
    res = client.post("/auth/login", data={"username": "ghost", "password": "x"})
    assert res.status_code == 400


def test_protected_route_without_token(client):
    assert client.get("/users/me").status_code == 401


def test_protected_route_invalid_token(client):
    res = client.get("/users/me", headers={"Authorization": "Bearer token.invalido"})
    assert res.status_code == 401


def test_sync_vulnerabilities_unauthorized(client, db_session):
    conn = _create_connection(db_session)
    response = client.post(f"/wazuh-connections/{conn.id}/sync")
    assert response.status_code == 401


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN)
def test_sync_vulnerabilities_success(mock_fetch, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session, name="test")
    headers = _get_headers(client)

    sync_res = client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)
    assert sync_res.status_code == 200
    assert sync_res.json()["synced"] == 1

    payload = client.get("/vulns", headers=headers).json()
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["cve_id"] == "CVE-2023-0001"
    assert item["connection_name"] == "test"
    assert item["package_name"] == "openssl"
    assert item["severity"] == "High"
    assert sorted(item["groups"]) == ["default", "linux"]


def test_change_password_success(client, db_session):
    _create_user(db_session)
    client.post("/auth/change-password",
                json={"old_password": "admin", "new_password": "Nueva123!", "confirm_password": "Nueva123!"},
                headers=_get_headers(client))
    res = client.post("/auth/login", data={"username": "admin", "password": "Nueva123!"})
    assert res.status_code == 200


def test_change_password_wrong_old(client, db_session):
    _create_user(db_session)
    res = client.post("/auth/change-password",
                      json={"old_password": "incorrecta", "new_password": "Nueva123!", "confirm_password": "Nueva123!"},
                      headers=_get_headers(client))
    assert res.status_code == 400


def test_change_password_same_as_old(client, db_session):
    _create_user(db_session)
    res = client.post("/auth/change-password",
                      json={"old_password": "admin", "new_password": "admin", "confirm_password": "admin"},
                      headers=_get_headers(client))
    assert res.status_code == 400


def test_change_password_unauthenticated(client):
    res = client.post("/auth/change-password",
                      json={"old_password": "admin", "new_password": "Nueva123!", "confirm_password": "Nueva123!"})
    assert res.status_code == 401


def test_change_password_mismatch(client, db_session):
    _create_user(db_session)
    res = client.post("/auth/change-password",
                      json={"old_password": "admin", "new_password": "Nueva123!", "confirm_password": "Otra456!"},
                      headers=_get_headers(client))
    assert res.status_code == 400


# users me


def test_get_me(client, db_session):
    _create_user(db_session)
    res = client.get("/users/me", headers=_get_headers(client))
    assert res.status_code == 200
    assert res.json()["username"] == "admin"
    assert res.json()["is_active"] is True


def test_get_me_is_active_false_after_deactivation(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    me = client.get("/users/me", headers=headers).json()

    user = db_session.query(User).filter_by(id=me["id"]).first()
    user.is_active = False
    db_session.commit()

    res = client.get("/users/me", headers=headers)
    assert res.json()["is_active"] is False


# users crud


def test_create_user(client, db_session):
    _create_user(db_session)
    res = client.post("/users", json={"username": "nuevo", "password": "pass123"},
                      headers=_get_headers(client))
    assert res.status_code == 200


def test_create_user_duplicate(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    client.post("/users", json={"username": "dup", "password": "x"}, headers=headers)
    res = client.post("/users", json={"username": "dup", "password": "y"}, headers=headers)
    assert res.status_code == 400


def test_create_user_unauthenticated(client):
    assert client.post("/users", json={"username": "x", "password": "y"}).status_code == 401


def test_list_users(client, db_session):
    _create_user(db_session)
    res = client.get("/users", headers=_get_headers(client))
    assert res.status_code == 200
    assert any(u["username"] == "admin" for u in res.json())


def test_delete_user(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    client.post("/users", json={"username": "todelete", "password": "x"}, headers=headers)
    users = client.get("/users", headers=headers).json()
    target_id = next(u["id"] for u in users if u["username"] == "todelete")
    assert client.delete(f"/users/{target_id}", headers=headers).status_code == 200


def test_delete_self_forbidden(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    me = client.get("/users/me", headers=headers).json()
    assert client.delete(f"/users/{me['id']}", headers=headers).status_code == 400


def test_delete_nonexistent_user(client, db_session):
    _create_user(db_session)
    assert client.delete("/users/9999", headers=_get_headers(client)).status_code == 404


# wazuh connections


def test_list_connections_empty(client, db_session):
    _create_user(db_session)
    res = client.get("/wazuh-connections", headers=_get_headers(client))
    assert res.status_code == 200
    assert res.json() == []


@patch("app.main.test_connection", return_value=True)
def test_create_connection(mock_test, client, db_session):
    _create_user(db_session)
    payload = {"name": "prod", "indexer_url": "https://wazuh:9200",
               "wazuh_user": "admin", "wazuh_password": "secret"}
    res = client.post("/wazuh-connections", json=payload, headers=_get_headers(client))
    assert res.status_code == 201
    mock_test.assert_called_once_with(
        payload["indexer_url"], payload["wazuh_user"], payload["wazuh_password"]
    )


def test_create_connection_duplicate_name(client, db_session):
    _create_user(db_session)
    headers = _get_headers(client)
    payload = {"name": "dup", "indexer_url": "x", "wazuh_user": "u", "wazuh_password": "p"}
    client.post("/wazuh-connections", json=payload, headers=headers)
    assert client.post("/wazuh-connections", json=payload, headers=headers).status_code == 400


@patch("app.main.test_connection", return_value=False)
def test_create_connection_fails_when_unreachable(mock_test, client, db_session):
    _create_user(db_session)
    payload = {"name": "bad", "indexer_url": "https://bad", "wazuh_user": "u", "wazuh_password": "p"}
    res = client.post("/wazuh-connections", json=payload, headers=_get_headers(client))
    assert res.status_code == 400
    assert "No se pudo establecer conexión" in res.json()["detail"]
    mock_test.assert_called_once()


def test_update_connection(client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    res = client.put(f"/wazuh-connections/{conn.id}",
                     json={"name": "updated", "indexer_url": "https://new.url",
                           "wazuh_user": "newuser", "wazuh_password": "newpass"},
                     headers=_get_headers(client))
    assert res.status_code == 200


def test_update_nonexistent_connection(client, db_session):
    _create_user(db_session)
    res = client.put("/wazuh-connections/9999",
                     json={"name": "x", "indexer_url": "x", "wazuh_user": "x", "wazuh_password": "x"},
                     headers=_get_headers(client))
    assert res.status_code == 404


def test_delete_connection(client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    assert client.delete(f"/wazuh-connections/{conn.id}", headers=_get_headers(client)).status_code == 200


@patch("app.main.fetch_all_vulns")
def test_delete_connection_removes_related_vulnerability_data(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln()
    _create_user(db_session)
    conn = _create_connection(db_session)
    headers = _get_headers(client)

    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)
    assert db_session.query(VulnerabilityFinding).count() == 1
    assert db_session.query(FindingHistory).count() == 1
    assert db_session.query(Asset).count() == 1
    assert db_session.query(AgentGroup).count() == 1
    assert db_session.query(VulnerabilityDetection).count() == 1

    res = client.delete(f"/wazuh-connections/{conn.id}", headers=headers)

    assert res.status_code == 200
    assert db_session.query(WazuhConnection).count() == 0
    assert db_session.query(VulnerabilityFinding).count() == 0
    assert db_session.query(FindingHistory).count() == 0
    assert db_session.query(Asset).count() == 0
    assert db_session.query(AgentGroup).count() == 0
    assert db_session.query(AssetGroupMember).count() == 0
    assert db_session.query(VulnerabilityDetection).count() == 0


def test_delete_nonexistent_connection(client, db_session):
    _create_user(db_session)
    assert client.delete("/wazuh-connections/9999", headers=_get_headers(client)).status_code == 404


@patch("app.main.test_connection", return_value=True)
def test_test_connection_ok(mock_test, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    res = client.post(f"/wazuh-connections/{conn.id}/test", headers=_get_headers(client))
    assert res.json()["ok"] is True


@patch("app.main.test_connection", return_value=False)
def test_test_connection_fail(mock_test, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    res = client.post(f"/wazuh-connections/{conn.id}/test", headers=_get_headers(client))
    assert res.json()["ok"] is False


def test_test_nonexistent_connection(client, db_session):
    _create_user(db_session)
    assert client.post("/wazuh-connections/9999/test", headers=_get_headers(client)).status_code == 404


# sync per conn


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN)
def test_sync_connection_success(mock_fetch, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    res = client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))
    assert res.status_code == 200
    assert res.json()["synced"] == 1


def test_sync_inactive_connection(client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session, is_active=False)
    assert client.post(f"/wazuh-connections/{conn.id}/sync",
                       headers=_get_headers(client)).status_code == 400


def test_sync_nonexistent_connection(client, db_session):
    _create_user(db_session)
    assert client.post("/wazuh-connections/9999/sync",
                       headers=_get_headers(client)).status_code == 404


# sync all


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN)
def test_sync_all_success(mock_fetch, client, db_session):
    _create_user(db_session)
    _create_connection(db_session, name="conn-1")
    _create_connection(db_session, name="conn-2")
    res = client.post("/vulns/sync-all", headers=_get_headers(client))
    body = res.json()
    assert body["connections_total"] == 2
    assert len(body["results"]) == 2
    assert all(r["ok"] for r in body["results"])


@patch("app.main.fetch_all_vulns", side_effect=Exception("unreachable"))
def test_sync_all_partial_failure(mock_fetch, client, db_session):
    _create_user(db_session)
    _create_connection(db_session)
    result = client.post("/vulns/sync-all", headers=_get_headers(client)).json()["results"][0]
    assert result["ok"] is False


def test_sync_all_skips_inactive(client, db_session):
    _create_user(db_session)
    _create_connection(db_session, is_active=False)
    assert client.post("/vulns/sync-all", headers=_get_headers(client)).status_code == 400


def test_sync_all_unauthenticated(client):
    assert client.post("/vulns/sync-all").status_code == 401


# vulns list


def test_list_vulns_empty(client, db_session):
    _create_user(db_session)
    payload = client.get("/vulns", headers=_get_headers(client)).json()
    assert payload["items"] == []
    assert payload["total"] == 0


def test_list_vulns_unauthenticated(client):
    assert client.get("/vulns").status_code == 401


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN)
def test_list_vulns_limit_zero(mock_fetch, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))
    assert client.get("/vulns?limit=0", headers=_get_headers(client)).json()["items"] == []


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN)
def test_list_vulns_shows_connection_name(mock_fetch, client, db_session):
    _create_user(db_session)
    conn = _create_connection(db_session, name="myconn")
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))
    items = client.get("/vulns", headers=_get_headers(client)).json()["items"]
    assert len(items) == 1
    assert items[0]["connection_name"] == "myconn"


# ingesta y modelo


@patch("app.main.fetch_all_vulns")
def test_new_vuln_creates_detected_history(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln()
    _create_user(db_session)
    conn = _create_connection(db_session)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))
    assert "DETECTED" in [h.action for h in db_session.query(FindingHistory).all()]


@patch("app.main.fetch_all_vulns")
def test_sync_creates_star_schema_entities(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln()
    _create_user(db_session)
    conn = _create_connection(db_session)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))

    assert db_session.query(Asset).count() == 1
    assert db_session.query(Package).count() == 1
    assert db_session.query(OperatingSystem).count() == 1
    assert db_session.query(VulnerabilityCatalog).count() == 1
    assert db_session.query(AgentGroup).count() == 1
    assert db_session.query(AssetGroupMember).count() == 1

    detection = db_session.query(VulnerabilityDetection).first()
    assert detection is not None
    assert detection.status == "Detected"

    package = db_session.query(Package).first()
    assert package.name == "curl"
    assert package.version == "7.81"


@patch("app.main.fetch_all_vulns")
def test_sync_enriches_groups_from_monitoring(mock_fetch, client, db_session):
    class MonitoringStream(list):
        agent_groups = {"001": ["deportes", "linux"]}

    document = _raw_vuln(groups=())[0]
    mock_fetch.return_value = MonitoringStream([document])
    _create_user(db_session)
    conn = _create_connection(db_session)

    client.post(
        f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client)
    )

    groups = db_session.query(AgentGroup).order_by(AgentGroup.name).all()
    assert [group.name for group in groups] == ["deportes", "linux"]
    assert db_session.query(AssetGroupMember).count() == 2


@patch("app.main.fetch_all_vulns")
def test_dimensions_are_not_duplicated_across_agents(mock_fetch, client, db_session):
    """Dos agentes con el mismo paquete/SO/CVE comparten una sola fila dimensión."""
    mock_fetch.return_value = (
        _raw_vuln(agent_id="001", agent_name="host-1")
        + _raw_vuln(agent_id="002", agent_name="host-2")
    )
    _create_user(db_session)
    conn = _create_connection(db_session)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))

    assert db_session.query(Asset).count() == 2
    assert db_session.query(VulnerabilityFinding).count() == 2
    assert db_session.query(Package).count() == 1
    assert db_session.query(OperatingSystem).count() == 1
    assert db_session.query(VulnerabilityCatalog).count() == 1


@patch("app.main.fetch_all_vulns")
def test_resolved_vuln_gets_reopened(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln()
    _create_user(db_session)
    conn = _create_connection(db_session)
    headers = _get_headers(client)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)

    finding = db_session.query(VulnerabilityFinding).first()
    finding.status = "RESOLVED"
    db_session.commit()

    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)
    db_session.refresh(finding)
    assert finding.status == "ACTIVE"
    assert finding.resolved_at is None
    assert "REOPENED" in [h.action for h in db_session.query(FindingHistory).all()]


@patch("app.main.fetch_all_vulns")
def test_vuln_resolved_when_absent_from_payload(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln()
    _create_user(db_session)
    conn = _create_connection(db_session)
    headers = _get_headers(client)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)

    mock_fetch.return_value = []
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)

    finding = db_session.query(VulnerabilityFinding).first()
    assert finding.status == "RESOLVED"
    assert finding.resolved_at is not None


@patch("app.main.fetch_all_vulns")
def test_severity_change_logged_in_history(mock_fetch, client, db_session):
    mock_fetch.return_value = _raw_vuln(severity="Low")
    _create_user(db_session)
    conn = _create_connection(db_session)
    headers = _get_headers(client)
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)

    mock_fetch.return_value = _raw_vuln(severity="Critical")
    client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)

    assert "SEVERITY_CHANGED" in [h.action for h in db_session.query(FindingHistory).all()]
    assert db_session.query(VulnerabilityCatalog).first().severity_rank == 4


@patch("app.main.fetch_all_vulns")
def test_vuln_without_cve_id_is_skipped(mock_fetch, client, db_session):
    mock_fetch.return_value = [{
        "agent": {"id": "001", "name": "host-1"},
        "host": {"os": {}},
        "package": {"name": "curl", "version": "7.81"},
        "vulnerability": {"id": None, "severity": "High", "score": {}},
    }]
    _create_user(db_session)
    conn = _create_connection(db_session)
    res = client.post(f"/wazuh-connections/{conn.id}/sync", headers=_get_headers(client))
    assert res.json()["synced"] == 0
    assert db_session.query(VulnerabilityFinding).count() == 0


# filtros


@pytest.fixture
def synced(client, db_session):
    """Dataset base: 3 agentes, 2 grupos, 3 severidades."""
    _create_user(db_session)
    conn = _create_connection(db_session, name="prod")
    headers = _get_headers(client)

    payload = (
        _raw_vuln(cve="CVE-2024-1111", severity="Critical", agent_id="001",
                  agent_name="web-1", groups=("default", "web"), package="nginx",
                  version="1.24", score=9.8)
        + _raw_vuln(cve="CVE-2024-2222", severity="Medium", agent_id="002",
                    agent_name="db-1", groups=("default", "db"), package="postgres",
                    version="15.1", score=5.4)
        + _raw_vuln(cve="CVE-2024-3333", severity="Low", agent_id="003",
                    agent_name="app-1", groups=("app",), package="python3",
                    version="3.11", score=2.1)
    )
    with patch("app.main.fetch_all_vulns", return_value=payload):
        client.post(f"/wazuh-connections/{conn.id}/sync", headers=headers)
    return {"conn": conn, "headers": headers}


def test_filter_by_status_resolved_and_unresolved(client, db_session, synced):
    headers = synced["headers"]
    finding = db_session.query(VulnerabilityFinding).first()
    finding.status = "RESOLVED"
    db_session.commit()

    activas = client.get("/vulns?status=no_resuelta", headers=headers).json()
    resueltas = client.get("/vulns?status=resuelta", headers=headers).json()

    assert activas["total"] == 2
    assert resueltas["total"] == 1
    assert all(item["status"] == "ACTIVE" for item in activas["items"])
    assert all(item["status"] == "RESOLVED" for item in resueltas["items"])


def test_filter_by_numeric_criticality_score(client, synced):
    headers = synced["headers"]
    altos = client.get("/vulns?score_min=6", headers=headers).json()
    assert altos["total"] == 1
    assert altos["items"][0]["cve_id"] == "CVE-2024-1111"

    rango = client.get("/vulns?score_min=2&score_max=6", headers=headers).json()
    assert {item["cve_id"] for item in rango["items"]} == {"CVE-2024-2222", "CVE-2024-3333"}


def test_filter_by_severity_rank(client, synced):
    payload = client.get("/vulns?rank_min=3", headers=synced["headers"]).json()
    assert payload["total"] == 1
    assert payload["items"][0]["severity"] == "Critical"


def test_filter_by_group(client, synced):
    headers = synced["headers"]
    default = client.get("/vulns?group=default", headers=headers).json()
    web = client.get("/vulns?group=web", headers=headers).json()

    assert default["total"] == 2
    assert web["total"] == 1
    assert web["items"][0]["agent_name"] == "web-1"


def test_filter_by_operating_system(client, synced):
    payload = client.get("/vulns?os_platform=ubuntu", headers=synced["headers"]).json()
    assert payload["total"] == 3
    assert client.get(
        "/vulns?os_platform=windows", headers=synced["headers"]
    ).json()["total"] == 0


def test_filter_options_include_groups_and_os(client, synced):
    data = client.get("/vulns/filter-options", headers=synced["headers"]).json()
    assert sorted(g["name"] for g in data["groups"]) == ["app", "db", "default", "web"]
    assert data["operating_systems"][0]["platform"] == "ubuntu"
    assert "Critical" in data["severities"]
    assert sorted(data["packages"]) == ["nginx", "postgres", "python3"]


def test_package_inventory_table(client, synced):
    payload = client.get("/vulns/packages", headers=synced["headers"]).json()
    assert payload["total"] == 3
    nginx = next(item for item in payload["items"] if item["name"] == "nginx")
    assert nginx["version"] == "1.24"
    assert nginx["activas"] == 1
    assert nginx["peor_severidad"] == "Critical"

    filtrado = client.get("/vulns/packages?search=ngin", headers=synced["headers"]).json()
    assert filtrado["total"] == 1


# dashboard


def test_dashboard_status_breakdown(client, db_session, synced):
    finding = db_session.query(VulnerabilityFinding).first()
    finding.status = "RESOLVED"
    db_session.commit()

    data = client.get("/vulns/dashboard/status-breakdown", headers=synced["headers"]).json()
    assert data["total"] == 3
    assert data["activas"] == 2
    assert data["resueltas"] == 1
    assert data["pct_resueltas"] == pytest.approx(33.3, abs=0.1)


def test_dashboard_new_unresolved_ratio(client, db_session, synced):
    from datetime import datetime, timezone

    year = datetime.now(timezone.utc).year
    finding = db_session.query(VulnerabilityFinding).first()
    finding.status = "RESOLVED"
    db_session.commit()

    data = client.get(
        f"/vulns/dashboard/new-unresolved?year={year}", headers=synced["headers"]
    ).json()
    assert data["anio"] == year
    assert data["nuevas"] == 3
    assert data["sin_corregir"] == 2
    assert data["pct_sin_corregir"] == pytest.approx(66.7, abs=0.1)


def test_dashboard_critical_coverage(client, synced):
    data = client.get("/vulns/dashboard/critical-coverage", headers=synced["headers"]).json()
    assert data["total_agentes"] == 3
    assert data["agentes_criticos"] == 1
    assert data["pct_agentes"] == pytest.approx(33.3, abs=0.1)
    assert data["total_grupos"] == 4
    assert data["grupos_criticos"] == 2  # default y web


def test_dashboard_critical_histogram(client, synced):
    data = client.get("/vulns/dashboard/critical-histogram", headers=synced["headers"]).json()
    assert len(data) == 1
    assert data[0]["hostname"] == "web-1"
    assert data[0]["criticas"] == 1
    assert "web" in data[0]["grupos"]


def test_dashboard_group_risk(client, synced):
    data = client.get("/vulns/dashboard/group-risk", headers=synced["headers"]).json()
    by_name = {row["name"]: row for row in data}
    assert by_name["web"]["criticas"] == 1
    assert by_name["default"]["agentes"] == 2
    assert by_name["app"]["criticas"] == 0


# evolución


def test_evolution_endpoints_return_dashboard_data(client, synced):
    headers = synced["headers"]
    summary = client.get("/vulns/evolution/summary", headers=headers).json()
    top_assets = client.get("/vulns/evolution/top-assets", headers=headers).json()

    assert summary["active_vulnerabilities"] == 3
    assert summary["assets"] == 3
    assert summary["groups"] == 4
    assert summary["packages"] == 3
    assert summary["detection_events"] == 3
    assert len(top_assets) == 3


def test_timeline_uses_month_periods(client, synced):
    data = client.get("/vulns/evolution/timeline?period=12m", headers=synced["headers"]).json()
    assert data["period"] == "12m"
    assert data["bucket"] == "month"
    assert sum(point["nuevas"] for point in data["points"]) == 3


def test_timeline_accepts_legacy_day_period(client, synced):
    data = client.get("/vulns/evolution/timeline?period=30d", headers=synced["headers"]).json()
    assert data["period"] == "1m"


def test_monthly_trend(client, synced):
    data = client.get("/vulns/evolution/monthly", headers=synced["headers"]).json()
    assert sum(point["total_vulnerabilidades"] for point in data) == 3


def test_threat_spans_expose_resolution_and_coverage(client, db_session, synced):
    finding = db_session.query(VulnerabilityFinding).first()
    finding.status = "RESOLVED"
    from datetime import datetime, timezone

    finding.resolved_at = datetime.now(timezone.utc)
    db_session.commit()

    data = client.get("/vulns/evolution/threats", headers=synced["headers"]).json()
    assert data["total"] == 3
    assert data["resolved"] == 1
    assert data["coverage"]["since"] is not None

    resuelta = next(item for item in data["items"] if item["status"] == "RESOLVED")
    assert resuelta["resolved_at"] is not None
    assert resuelta["start"] is not None


def test_threat_spans_filter_by_group(client, synced):
    data = client.get("/vulns/evolution/threats?group=db", headers=synced["headers"]).json()
    assert data["total"] == 1
    assert data["items"][0]["agent_name"] == "db-1"


def test_vuln_history_endpoint(client, db_session, synced):
    finding = db_session.query(VulnerabilityFinding).first()
    data = client.get(f"/vulns/{finding.id}/history", headers=synced["headers"]).json()
    assert data["id"] == finding.id
    assert data["history"][0]["action"] == "DETECTED"


def test_vuln_history_not_found(client, synced):
    assert client.get("/vulns/999999/history", headers=synced["headers"]).status_code == 404
