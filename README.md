# Auth API

REST API de autenticación con JWT construida con FastAPI. Implementa registro, login, refresh de tokens y logout con sesión única por usuario.

![CI](https://github.com/Euchelu/auth-api/actions/workflows/ci.yml/badge.svg)

## Tecnologías

- **FastAPI** — framework web async
- **SQLAlchemy** — ORM (SQLite local / PostgreSQL en Docker)
- **python-jose** — firma y verificación de JWT
- **bcrypt** — hashing de contraseñas
- **Pydantic v2** — validación de datos con `EmailStr`
- **Docker + Docker Compose** — despliegue con PostgreSQL
- **pytest + httpx** — 18 tests de integración

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/auth/register` | Registrar nuevo usuario |
| `POST` | `/auth/login` | Login → access + refresh token |
| `POST` | `/auth/refresh` | Renovar access token |
| `POST` | `/auth/logout` | Revocar refresh token |
| `GET` | `/users/me` | Perfil del usuario autenticado |

## Seguridad JWT

- **Access token**: duración 30 min, se envía en cada request (`Authorization: Bearer ...`)
- **Refresh token**: duración 7 días, persiste en DB para sesión única
- Los tokens incluyen claim `"type": "access" | "refresh"` para evitar sustitución de tokens
- Logout invalida el refresh token en DB

## Instalación local

```bash
# Requiere Python 3.12 o 3.13
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements-dev.txt

# Ejecutar tests
pytest tests/ -v

# Levantar servidor
uvicorn app.main:app --reload
```

Docs disponibles en `http://localhost:8000/docs`

## Docker

```bash
docker compose up --build
```

La API queda en `http://localhost:8000` con PostgreSQL como base de datos.

## Ejemplo de flujo

```bash
# 1. Registrar usuario
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"user1","password":"secret123"}'

# 2. Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret123"}'
# → {"access_token":"...", "refresh_token":"...", "token_type":"bearer"}

# 3. Acceder a ruta protegida
curl http://localhost:8000/users/me \
  -H "Authorization: Bearer <access_token>"

# 4. Renovar access token
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"..."}'
```

## Tests

```
tests/test_auth.py  18 tests
  ✓ Registro exitoso
  ✓ Email duplicado → 409
  ✓ Username duplicado → 409
  ✓ Contraseña corta → 422
  ✓ Email inválido → 422
  ✓ Login exitoso
  ✓ Contraseña incorrecta → 401
  ✓ Email desconocido → 401
  ✓ GET /users/me con token válido
  ✓ GET /users/me sin token → 403
  ✓ GET /users/me con token inválido → 401
  ✓ Refresh token rechazado en /users/me → 401
  ✓ Refresh exitoso
  ✓ Refresh con token inválido → 401
  ✓ Access token rechazado en /refresh → 401
  ✓ Logout exitoso
  ✓ Refresh falla tras logout → 401
```
