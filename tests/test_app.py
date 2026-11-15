import pytest

from devguard.config import ConfigError, load_settings


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "object-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in r.headers["permissions-policy"]


def test_index_served_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "DevGuard" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]


def test_docs_use_only_local_assets(client):
    r = client.get("/docs")
    csp = r.headers["content-security-policy"]
    assert r.status_code == 200 and "swagger-ui" in r.text
    assert "http://" not in r.text and "https://" not in r.text      # nothing loaded from a CDN
    assert "https:" not in csp and "script-src 'self';" in csp
    for path in ("/static/vendor/swagger-ui/swagger-ui-bundle.js", "/static/vendor/swagger-ui/swagger-ui.css",
                 "/static/js/docs-init.js", "/openapi.json"):
        assert client.get(path).status_code == 200
    assert client.get("/redoc").status_code == 404


def test_missing_or_unknown_host_rejected(settings):
    from fastapi.testclient import TestClient
    from devguard.app import create_app
    with TestClient(create_app(settings)) as c:      # default Host is "testserver"
        r = c.get("/api/health")
    assert r.status_code == 403 and r.json()["error"] == "host_not_allowed"


def test_foreign_origin_rejected(client):
    r = client.post("/api/health", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"] == "origin_not_allowed"


def test_cross_site_fetch_metadata_rejected_on_api_get(client):
    r = client.get("/api/scans", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403 and r.json()["error"] == "origin_not_allowed"


def test_dns_rebinding_host_header_rejected(client):
    r = client.get("/api/scans", headers={"Host": "evil.attacker.example:8000"})
    assert r.status_code == 403 and r.json()["error"] == "host_not_allowed"


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
