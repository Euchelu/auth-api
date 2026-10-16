import importlib
import os

import pytest

from app import auth as auth_module


def _reload_auth():
    return importlib.reload(auth_module)


def test_refuses_default_secret_in_production(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        _reload_auth()


def test_allows_default_secret_in_development(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    module = _reload_auth()
    assert module.SECRET_KEY == module.DEV_SECRET_KEY


def test_allows_production_with_real_secret(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "a-real-secret-not-the-default")
    module = _reload_auth()
    assert module.SECRET_KEY == "a-real-secret-not-the-default"


@pytest.fixture(autouse=True)
def restore_module_state():
    # Leave auth.py in its normal (development) state for the rest of the suite.
    yield
    os.environ.pop("ENV", None)
    os.environ.pop("SECRET_KEY", None)
    _reload_auth()
