import pytest

from app import wazuh_client


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_stream_pages_without_accumulating_all_documents(monkeypatch):
    monkeypatch.setenv("WAZUH_BATCH_SIZE", "2")
    monkeypatch.setenv("WAZUH_VERIFY_TLS", "false")
    calls = []
    responses = iter(
        [
            {
                "hits": {
                    "total": {"value": 3, "relation": "eq"},
                    "hits": [
                        {"_source": {"id": 1}, "sort": ["2026-01-01", "a"]},
                        {"_source": {"id": 2}, "sort": ["2026-01-02", "b"]},
                    ],
                }
            },
            {
                "hits": {
                    "total": {"value": 3, "relation": "eq"},
                    "hits": [
                        {"_source": {"id": 3}, "sort": ["2026-01-03", "c"]}
                    ],
                }
            },
        ]
    )

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(next(responses))

    monkeypatch.setattr(wazuh_client.requests, "post", fake_post)
    stream = wazuh_client.fetch_all_vulns("https://indexer.local/", "usuario", "clave")

    assert len(stream) == 3
    assert len(calls) == 1
    assert [item["id"] for item in stream] == [1, 2, 3]
    assert len(calls) == 2
    assert calls[0][1]["verify"] is False
    assert "search_after" not in calls[0][1]["json"]
    assert calls[1][1]["json"]["search_after"] == ["2026-01-02", "b"]
    assert len(stream) == 3
    assert len(calls) == 2

    with pytest.raises(RuntimeError, match="solo puede recorrerse una vez"):
        list(stream)


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("true", True), ("false", False), ("/certs/wazuh-ca.pem", "/certs/wazuh-ca.pem")],
)
def test_tls_verification_configuration(monkeypatch, configured, expected):
    monkeypatch.setenv("WAZUH_VERIFY_TLS", configured)
    assert wazuh_client._tls_verification() == expected


def test_fetch_agent_groups_uses_latest_monitoring_record(monkeypatch):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({
            "hits": {"hits": [
                {"_source": {"id": "010", "name": "kali", "group": ["default"]}},
                {"_source": {"id": "013", "name": "ubuntu", "group": "deportes, web"}},
            ]}
        })

    monkeypatch.setattr(wazuh_client.requests, "post", fake_post)
    result = wazuh_client.fetch_agent_groups(
        "https://indexer.local/wazuh-monitoring-*/_search",
        {"Authorization": "Basic test"},
    )

    assert result == {"010": ["default"], "013": ["deportes", "web"]}
    request = calls[0][1]["json"]
    assert request["collapse"] == {"field": "id"}
    assert request["sort"][0]["timestamp"]["order"] == "desc"
