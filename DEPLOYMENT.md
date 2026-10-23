# TrustVault — Production Deployment & Operations Guide

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Target Environments:** Render, Railway, Heroku, AWS ECS / DigitalOcean VPS
**Security Standard:** Zero-Trust Architecture, OWASP ASVS Level 2

---

## 1. Production Architecture Overview

In production, TrustVault operates as a containerized or WSGI-managed Django application backed by:
- **Web Application Server:** `gunicorn` with asynchronous worker threads (`--workers 3 --timeout 120`).
- **Relational Database:** Managed PostgreSQL 14+ connected via TLS and pooled connections.
- **Static Asset Delivery:** `WhiteNoise` with compressed manifest cache headers (`max-age=31536000`).
- **Protected File Storage:** Dedicated private persistent volume mount (`PROTECTED_MEDIA_ROOT`), never mapped to web server static locations.
- **Reverse Proxy / TLS Termination:** Cloudflare, AWS ALB, or Nginx handling HTTPS termination and injecting `X-Forwarded-Proto`.

---

## 2. Environment Variables Specification

The following environment variables must be configured in production:

| Variable | Required | Recommended Production Value | Description |
| :--- | :--- | :--- | :--- |
| `DEBUG` | **Yes** | `False` | Disables debug mode and detailed error traces |
| `SECRET_KEY` | **Yes** | Cryptographically random string (min 50 chars) | Django cryptographic signing key |
| `ALLOWED_HOSTS` | **Yes** | `trustvault.example.com,.onrender.com` | Whitelist of valid Host header hostnames |
| `DATABASE_URL` | **Yes** | `postgres://user:pass@host:5432/trustvault` | PostgreSQL database connection string |
| `CSRF_TRUSTED_ORIGINS`| **Yes** | `https://trustvault.example.com` | Trusted origins for CSRF POST requests |
| `SECURE_SSL_REDIRECT` | **Yes** | `True` | Forces all HTTP requests to redirect to HTTPS |
| `SESSION_COOKIE_SECURE`| **Yes**| `True` | Restricts session cookies to HTTPS transmissions |
| `CSRF_COOKIE_SECURE` | **Yes** | `True` | Restricts CSRF cookies to HTTPS transmissions |
| `SECURE_PROXY_SSL_HEADER`| **Yes**| `True` | Instructs Django to trust `X-Forwarded-Proto: https` |
| `SECURE_HSTS_SECONDS` | **Yes** | `31536000` (1 year) | Enforces HTTP Strict Transport Security |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS`| No | `True` | Applies HSTS to all subdomains |
| `SECURE_HSTS_PRELOAD` | No | `True` | Permits browser HSTS preload list enrollment |
| `PROTECTED_MEDIA_DIR` | No | `/var/data/trustvault_storage` | Persistent storage directory for protected files |
| `MAX_UPLOAD_SIZE_MB` | No | `25` | Maximum upload size threshold |

---

## 3. Platform Deployment Guides

### Option A: Render.com (Automated via Blueprint)
1. Fork or push the TrustVault repository to GitHub.
2. In Render Dashboard, click **New +** -> **Blueprint**.
3. Select the repository. Render will automatically parse `render.yaml`.
4. It will provision:
   - A managed PostgreSQL database (`trustvault-postgres`).
   - A Python web service executing `./build.sh` and starting Gunicorn.
   - Inject all security environment variables and database URLs.
5. Once deployed, run the demo seeder via the Render Shell tab:
   ```bash
   python manage.py seed_demo_data
   ```

### Option B: Railway.app / Heroku
1. Create a new project and attach a PostgreSQL database.
2. Configure environment variables in the project settings.
3. Railway/Heroku will detect `Procfile` and `runtime.txt` automatically.
4. Deployment command executes:
   ```bash
   python manage.py migrate --noinput
   python manage.py collectstatic --noinput
   ```

### Option C: Vercel Serverless + Neon PostgreSQL & Object Storage (Production Deployed)
TrustVault is deployed and verified live on **Vercel** ([https://trustvault-lemon.vercel.app](https://trustvault-lemon.vercel.app)):
1. **Serverless Execution:** Powered by Vercel WSGI entrypoint (`trustvault/wsgi.py`) and zero-downtime builds (`vercel.json`).
2. **Managed PostgreSQL:** Hosted on **Neon Serverless PostgreSQL** with PgBouncer connection pooling (`DATABASE_URL`), `CONN_MAX_AGE=0` to prevent connection exhaustion in serverless workers, and `DISABLE_SERVER_SIDE_CURSORS=True`.
3. **Private Document Storage:** Hosted on private **Neon Object Storage** (`trustvault-documents` S3 bucket). Document binaries are never exposed publicly; all downloads stream through authenticated and authorized Django controllers (`/documents/<id>/download/`) with SHA-256 integrity checks.
4. **Static Assets:** Handled via WhiteNoise with compressed asset caching and `/tmp/staticfiles` generation during serverless execution.
5. **Fail-Closed Security:** Strict production checks prevent silent fallback to SQLite or local filesystem storage in production.

### Option D: Docker / Linux VPS (Ubuntu 22.04 LTS)
Sample Nginx reverse proxy configuration:
```nginx
server {
    listen 80;
    server_name trustvault.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name trustvault.example.com;

    ssl_certificate /etc/letsencrypt/live/trustvault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/trustvault.example.com/privkey.pem;

    # Baseline Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Static assets served by Nginx or WhiteNoise
    location /static/ {
        alias /var/www/trustvault/staticfiles/;
        expires 30d;
        access_log off;
    }

    # CRUCIAL: NEVER map /protected_media/ in Nginx
    # Protected media must only be streamed via Gunicorn controller endpoints

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Production Security Verification Checklist

Before opening TrustVault to public network traffic:
- [x] `DEBUG` is set strictly to `False`.
- [x] `SECRET_KEY` is randomly generated and not hardcoded.
- [x] Database connections use TLS.
- [x] `PROTECTED_MEDIA_ROOT` is mounted to a persistent volume with permissions `chmod 700`.
- [x] `PROTECTED_MEDIA_ROOT` is completely excluded from Nginx/Apache static location blocks.
- [x] SSL redirection (`SECURE_SSL_REDIRECT=True`) is active.
- [x] Session & CSRF cookies have `Secure=True` and `SameSite=Lax`.
- [x] Health check endpoint `GET /health/` returns `200 OK` with database and storage connected.
- [x] Default admin credentials are changed or managed through environment secrets.
