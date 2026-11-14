import pytest

from devguard.config import ConfigError, load_settings


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_index_served_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "DevGuard" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]


def test_foreign_origin_rejected(client):
    r = client.post("/api/health", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"] == "origin_not_allowed"


def test_non_json_post_rejected(client):
    r = client.post("/api/health", content="x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 403 and r.json()["error"] == "json_required"


def test_unknown_route_uses_error_shape(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and set(r.json()) == {"error", "message"}


def test_non_loopback_host_refused(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[server]\nhost="0.0.0.0"\n')
    with pytest.raises(ConfigError):
        load_settings(cfg)
