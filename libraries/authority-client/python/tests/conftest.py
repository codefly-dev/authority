import pytest

@pytest.fixture(autouse=True)
def local_environment(monkeypatch):
    monkeypatch.setenv("CODEFLY__ENVIRONMENT", "local")
