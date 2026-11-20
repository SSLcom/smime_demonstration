import json
from pathlib import Path

import pytest

from smime_demo.config import Settings
from tests.unit.pki import DemoPki

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SANDBOX_RUN = FIXTURES / "sandbox" / "20261120-163255-8f4a"


def load_fixture(prefix: str) -> dict:
    """A recorded sandbox exchange by its number, e.g. load_fixture("24")."""
    (path,) = SANDBOX_RUN.glob(f"{prefix}_*.json")
    return json.loads(path.read_text())


@pytest.fixture
def fixture():
    return load_fixture


@pytest.fixture(scope="session")
def pki() -> DemoPki:
    return DemoPki.create()


@pytest.fixture
def settings() -> Settings:
    return Settings("sandbox", "test-account-key", "test-secret-key", "user@example.com")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    """Keep a developer's real .env and SSLCOM_* variables out of unit tests."""
    import os

    for name in list(os.environ):
        if name.startswith("SSLCOM_"):
            monkeypatch.delenv(name)
    monkeypatch.setattr("smime_demo.config.load_dotenv", lambda *a, **k: None)
