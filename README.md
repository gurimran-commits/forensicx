# ForensicX

ForensicX is a FastAPI backend for case management, evidence registration, chain-of-custody events, and bounded forensic analysis.

## Setup

Use Python 3.12 or later. Create and activate a virtual environment, then install the application and its development tools:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the test suite with:

```bash
python -m pytest
```

## Configuration

Configuration is read from environment variables when the application starts. Defaults are shown below.

| Variable | Default | Notes |
| --- | --- | --- |
| `FORENSICX_DATABASE_PATH` | `data/forensicx.sqlite3` | SQLite database location. |
| `FORENSICX_STORAGE_PATH` | `storage` | Root directory for stored evidence files. |
| `FORENSICX_MAX_UPLOAD_SIZE` | `1073741824` | Maximum upload size in bytes (1 GiB). |
| `FORENSICX_ALLOWED_EXTENSIONS` | `.zip,.7z,.rar,.pcap,.pcapng,.img,.iso,.e01,.raw,.mem,.dmp,.bin,.exe,.dll,.pdf,.docx,.xlsx,.csv,.json,.xml,.txt,.jpg,.jpeg,.png` | Comma-separated permitted file extensions. |
| `FORENSICX_JWT_SECRET` | generated per process in development | Required when `FORENSICX_ENV=production`. |
| `FORENSICX_ACCESS_TOKEN_MINUTES` | `60` | JWT lifetime in minutes. |
| `FORENSICX_CORS_ORIGINS` | `http://127.0.0.1:8765,http://127.0.0.1:8770` | Comma-separated allowed origins. |
| `FORENSICX_ENV` | `development` | Set to `production` to require a JWT secret and disable the development-token endpoint. |
| `FORENSICX_LOG_LEVEL` | `INFO` | Python logging level. |
| `FORENSICX_RATE_LIMIT_PER_MINUTE` | `120` | Per-client request limit. |

For production, provide a persistent, high-entropy JWT secret before starting the service:

```bash
export FORENSICX_ENV=production
export FORENSICX_JWT_SECRET="replace-with-a-long-random-secret"
```

## Run

Start the API from the repository root:

```bash
uvicorn forensicx.main:app --host 127.0.0.1 --port 8770
```

Interactive API documentation is available at `http://127.0.0.1:8770/api/docs`.
