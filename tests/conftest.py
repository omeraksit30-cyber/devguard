import pytest
from fastapi.testclient import TestClient

from devguard.app import create_app
from devguard.config import load_settings


@pytest.fixture
def settings(tmp_path, monkeypatch):
    cfg = tmp_path / "devguard.toml"
    roots = tmp_path / "roots"
    roots.mkdir()
    cfg.write_text(
        f'[server]\nhost="127.0.0.1"\nport=8000\n'
        f'[storage]\ndatabase="{tmp_path / "test.db"}"\n'
        f'[scan]\nallowed_roots=["{roots}"]\ntimeout_seconds=30\n'
    )
    return load_settings(cfg)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000") as c:
        yield c
