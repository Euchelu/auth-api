import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db

TEST_DATABASE_URL = "sqlite:///./test_auth.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    app.state.limiter.reset()  # every test gets a fresh login rate-limit bucket
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)

VALID_USER = {
    "email": "jose@example.com",
    "username": "euchelu",
    "password": "SecurePass123",
}


def register_and_login(data=None):
    """Helper: registra un usuario y devuelve los tokens."""
    data = data or VALID_USER
    client.post("/auth/register", json=data)
    response = client.post("/auth/login", json={
        "email": data["email"],
        "password": data["password"],
    })
    return response.json()


# ── Health ────────────────────────────────────────────────────────────────────

def test_health():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Register ──────────────────────────────────────────────────────────────────

def test_register_success():
    r = client.post("/auth/register", json=VALID_USER)
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == VALID_USER["email"]
    assert data["username"] == VALID_USER["username"]
    assert "hashed_password" not in data  # nunca se expone

def test_register_duplicate_email():
    client.post("/auth/register", json=VALID_USER)
    r = client.post("/auth/register", json=VALID_USER)
    assert r.status_code == 409
    assert "Email" in r.json()["detail"]

def test_register_duplicate_username():
    client.post("/auth/register", json=VALID_USER)
    r = client.post("/auth/register", json={**VALID_USER, "email": "other@example.com"})
    assert r.status_code == 409
    assert "Username" in r.json()["detail"]

def test_register_short_password():
    r = client.post("/auth/register", json={**VALID_USER, "password": "123"})
    assert r.status_code == 422

def test_register_invalid_email():
    r = client.post("/auth/register", json={**VALID_USER, "email": "not-an-email"})
    assert r.status_code == 422


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_success():
    client.post("/auth/register", json=VALID_USER)
    r = client.post("/auth/login", json={
        "email": VALID_USER["email"],
        "password": VALID_USER["password"],
    })
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_wrong_password():
    client.post("/auth/register", json=VALID_USER)
    r = client.post("/auth/login", json={
        "email": VALID_USER["email"],
        "password": "wrongpassword",
    })
    assert r.status_code == 401

def test_login_unknown_email():
    r = client.post("/auth/login", json={
        "email": "nobody@example.com",
        "password": "anypass",
    })
    assert r.status_code == 401


# ── Protected route /users/me ─────────────────────────────────────────────────

def test_get_me_success():
    tokens = register_and_login()
    r = client.get("/users/me", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    assert r.status_code == 200
    assert r.json()["email"] == VALID_USER["email"]

def test_get_me_no_token():
    r = client.get("/users/me")
    assert r.status_code == 403

def test_get_me_invalid_token():
    r = client.get("/users/me", headers={"Authorization": "Bearer invalidtoken"})
    assert r.status_code == 401

def test_get_me_refresh_token_rejected():
    """El refresh token NO debe servir para acceder a rutas protegidas."""
    tokens = register_and_login()
    r = client.get("/users/me", headers={
        "Authorization": f"Bearer {tokens['refresh_token']}"
    })
    assert r.status_code == 401


# ── Refresh token ─────────────────────────────────────────────────────────────

def test_refresh_success():
    tokens = register_and_login()
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    assert "access_token" in r.json()

def test_refresh_invalid_token():
    r = client.post("/auth/refresh", json={"refresh_token": "invalid"})
    assert r.status_code == 401

def test_refresh_access_token_rejected():
    """El access token NO debe funcionar como refresh token."""
    tokens = register_and_login()
    r = client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401


# ── Logout ────────────────────────────────────────────────────────────────────

def test_logout_success():
    tokens = register_and_login()
    r = client.post("/auth/logout", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    assert r.status_code == 200
    assert "Logged out" in r.json()["message"]

def test_refresh_fails_after_logout():
    """Después del logout el refresh token queda invalidado."""
    tokens = register_and_login()
    client.post("/auth/logout", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401

# ── Rate limiting ────────────────────────────────────────────────────────────

def test_login_rate_limited_after_five_attempts():
    """El 6º intento de login en el mismo minuto debe recibir 429, aunque la contraseña sea correcta."""
    client.post("/auth/register", json=VALID_USER)
    for _ in range(5):
        r = client.post("/auth/login", json={
            "email": VALID_USER["email"],
            "password": VALID_USER["password"],
        })
        assert r.status_code == 200
    r = client.post("/auth/login", json={
        "email": VALID_USER["email"],
        "password": VALID_USER["password"],
    })
    assert r.status_code == 429
