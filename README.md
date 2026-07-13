# ForensicX

ForensicX is a modular Digital Forensics and Incident Response platform built with FastAPI, Pydantic v2, SQLAlchemy 2, and a dark dashboard UI.

## Implemented Modules

- Dashboard REST API with JWT/RBAC protection.
- Case Management REST API with SQLAlchemy ORM persistence.
- Browser dashboard connected to the REST API.

## Local Run

```powershell
python -m uvicorn forensicx.main:app --host 127.0.0.1 --port 8770
```

Open:

- Dashboard: http://127.0.0.1:8770/dashboard
- API docs: http://127.0.0.1:8770/api/docs

## Configuration

Environment variables:

- `FORENSICX_DATABASE_PATH`: SQLite database path for local development.
- `FORENSICX_JWT_SECRET`: JWT signing secret. Required in production.
- `FORENSICX_ACCESS_TOKEN_MINUTES`: Access token lifetime.
- `FORENSICX_CORS_ORIGINS`: Comma-separated allowed origins.
- `FORENSICX_RATE_LIMIT_PER_MINUTE`: Per-client request limit.

## Verification

```powershell
python -m compileall forensicx tests
python -m pytest
```

## Architecture

The backend follows feature-based Clean Architecture boundaries:

- `platform`: shared configuration, database, security, middleware, and error handling.
- `modules/<feature>/api.py`: FastAPI route adapters.
- `modules/<feature>/service.py`: application use cases.
- `modules/<feature>/repository.py`: persistence adapter.
- `modules/<feature>/models.py`: SQLAlchemy ORM models.
- `modules/<feature>/schemas.py`: Pydantic DTOs.

No module should reach into another module's internals. Integration should happen through services, DTOs, or explicit platform contracts.
