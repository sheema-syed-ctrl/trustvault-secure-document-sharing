# TrustVault — SQLite to PostgreSQL (Neon) Migration Guide

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Author:** TrustVault Security & Infrastructure Team  
**Scope:** Production Database Migration from SQLite (`/var/task/db.sqlite3`) to PostgreSQL hosted on Neon  
**Security Level:** Zero-Trust Data Architecture, OWASP ASVS Level 2  

---

## 1. Executive Summary & Architecture Context

TrustVault utilizes SQLite for local development and PostgreSQL for production deployments. In serverless environments such as Vercel, the application runtime filesystem (`/var/task`) is strictly read-only. Attempting to write to SQLite in serverless produces:

```
sqlite3.OperationalError: attempt to write a readonly database
```

To provide persistent storage, concurrency, and security, TrustVault migrates production storage to **PostgreSQL hosted on Neon**.

### Key Architectural Safeguards:
1. **No Silent Fallback:** In production (`VERCEL=1` or `DJANGO_ENV=production`), `trustvault/settings.py` raises `ImproperlyConfigured` if `DATABASE_URL` is missing. It will never silently fall back to an ephemeral or read-only SQLite database.
2. **Serverless Connection Lifecycle:** Vercel functions scale dynamically and freeze/thaw between invocations. To avoid exhausting connection pools, `CONN_MAX_AGE=0` is enforced in production so database connections close gracefully at the end of each request.
3. **PgBouncer & Neon Compatibility:** Neon connection poolers operate in PgBouncer transaction pooling mode. `DISABLE_SERVER_SIDE_CURSORS = True` is configured in database options to prevent transaction pooler cursor incompatibilities.
4. **Mandatory TLS:** All connections to Neon require TLS encryption (`sslmode=require`).
5. **Decoupled Document Storage:** The PostgreSQL database stores document metadata, permissions, and audit logs. The actual binary document files (`.bin`) are stored in `PROTECTED_MEDIA_ROOT` and must be transferred independently.

---

## 2. Environment Variables Configuration

In your hosting platform (Vercel Project Settings &rarr; Environment Variables):

| Environment Variable | Required | Recommended Production Value | Description |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | **Yes** | `postgresql://<user>:<password>@<ep-pooler-id>.us-east-2.aws.neon.tech/<dbname>?sslmode=require` | Neon connection string with pooled endpoint |
| `CONN_MAX_AGE` | No | `0` | Closes TCP sockets on request finish in serverless |
| `DB_ENGINE` | No | `sqlite` (dev) / `postgresql` (prod) | Engine selector fallback when `DATABASE_URL` unset |
| `DEBUG` | **Yes** | `False` | Must remain False in production |
| `ALLOWED_HOSTS` | **Yes** | `sheema-ivory.vercel.app,.vercel.app` | Allowed hostnames |
| `PROTECTED_MEDIA_DIR` | No | `protected_media` | Private storage directory for document binaries |

> [!IMPORTANT]
> Always use Neon's **pooled endpoint** (`-pooler` hostname) for serverless environments. This routes queries through PgBouncer, preventing connection exhaustion during traffic bursts.

---

## 3. Step-by-Step Data Migration Procedure

### Step 1: Backup SQLite Database
Before performing any operations, create a secure, timestamped backup of the local SQLite database:

```bash
# Windows PowerShell
Copy-Item db.sqlite3 ("db_backup_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".sqlite3")

# Linux / macOS
cp db.sqlite3 "db_backup_$(date +%Y%m%d_%H%M%S).sqlite3"
```

### Step 2: Export Data via Django Natural Keys
Export existing rows from SQLite into a normalized JSON fixture. Omit Django's auto-generated permission and content-type tables to prevent primary key collisions:

```bash
python manage.py dumpdata \
    --natural-foreign \
    --natural-primary \
    -e contenttypes \
    -e auth.Permission \
    --indent 2 \
    -o trustvault_sqlite_data.json
```

Verify that the generated fixture contains:
- `accounts.user`
- `documents.document`
- `permissions.documentpermission`
- `audit.auditevent`

### Step 3: Initialize PostgreSQL Schema on Neon
Configure `DATABASE_URL` in your shell (pointing to your Neon instance) and run standard migrations:

```bash
# Set DATABASE_URL in shell temporarily (do not log credentials)
# Windows PowerShell:
$env:DATABASE_URL="postgresql://<user>:<password>@<ep-pooler-id>.us-east-2.aws.neon.tech/<dbname>?sslmode=require"

# Linux / macOS:
export DATABASE_URL="postgresql://<user>:<password>@<ep-pooler-id>.us-east-2.aws.neon.tech/<dbname>?sslmode=require"

# Apply initial Django schema
python manage.py migrate --noinput
```

### Step 4: Import Data into PostgreSQL
Load the exported fixture into the PostgreSQL database:

```bash
python manage.py loaddata trustvault_sqlite_data.json
```

Because `AuditEvent.save()` permits insertions for new primary keys and enforces immutability only against updates to existing records, the tamper-resistant audit records load with their original timestamps, historical snapshots, and UUIDs preserved.

### Step 5: Synchronize PostgreSQL Primary Key Sequences
When records are inserted with explicit primary keys (`id=1, 2, ...`), PostgreSQL auto-incrementing identity sequences must be synchronized to the maximum existing ID. Run the following command:

```bash
# Generate SQL statements to reset sequences
python manage.py sqlsequencereset accounts documents permissions audit
```

Execute the generated `SELECT setval(...)` statements against your Neon database using `python manage.py dbshell` or through Neon's SQL Console.

---

## 4. Physical Document Storage Migration (`PROTECTED_MEDIA_ROOT`)

> [!CAUTION]
> The database migration transfers document **metadata**, not binary file contents.

The `Document` model stores:
- `storage_filename`: A unique UUID-based filename (e.g. `3cc0de265a81402f97908fa336237649.bin`).
- `original_filename`: The human-readable name (e.g. `financial_audit.pdf`).
- `sha256_hash`: Integrity checksum for cryptographic verification.

The physical binary files reside on the filesystem under `PROTECTED_MEDIA_ROOT` (`protected_media/`).

### Verification & Sync Procedure:
1. Verify that all referenced `storage_filename` entries in the database exist on disk:
   ```bash
   python -c "
   import django, os; os.environ['DJANGO_SETTINGS_MODULE']='trustvault.settings'; django.setup()
   from documents.models import Document
   from django.conf import settings
   missing = [d.storage_filename for d in Document.objects.all() if not (settings.PROTECTED_MEDIA_ROOT / d.storage_filename).exists()]
   print('Missing physical files:', missing)
   "
   ```
2. When deploying to persistent cloud storage (e.g., AWS S3, Azure Blob, or persistent volume mounts), synchronize the contents of `protected_media/` to the target storage location.
3. Ensure permissions on `PROTECTED_MEDIA_ROOT` are restricted (`chmod 700` in Linux). Never expose `PROTECTED_MEDIA_ROOT` as a public web root or static directory.

---

## 5. Post-Migration Verification Checklist

Execute the following verification script against the PostgreSQL database to validate zero data loss:

```bash
python -c "
import django, os; os.environ['DJANGO_SETTINGS_MODULE']='trustvault.settings'; django.setup()
from accounts.models import User
from documents.models import Document
from permissions.models import DocumentPermission
from audit.models import AuditEvent

print('--- TrustVault Data Verification ---')
print(f'Users:       {User.objects.count()} (Expected >= 4)')
print(f'Documents:   {Document.objects.count()} (Expected >= 4)')
print(f'Permissions: {DocumentPermission.objects.count()} (Expected >= 2)')
print(f'AuditEvents: {AuditEvent.objects.count()} (Expected >= 43)')
"
```

### Verification Criteria:
- [x] All existing user accounts (`admin_demo`, `owner_demo`, `viewer_demo`) can authenticate with their existing passwords.
- [x] Document metadata, categories, and SHA-256 hashes match.
- [x] Object-level permissions (`READ`, `EDIT`) correctly govern document access.
- [x] Audit trail contains historical snapshots (`target_document_name_snapshot`, `target_username`).
- [x] New user registration generates a new user row and sequence auto-increments without collision.
- [x] Attempting to update or delete any `AuditEvent` raises `ValidationError` (tamper resistance intact).
- [x] `/health/` endpoint returns HTTP 200 with `status: healthy` and `database: connected`.

---

## 6. Rollback & Disaster Recovery Plan

If any issue occurs during the cutover:
1. **Local Development:** The original SQLite database (`db.sqlite3` and timestamped backups) remains untouched. Remove `DATABASE_URL` from the local environment to return to SQLite.
2. **Production Rollback:** If the Neon connection string is invalid or unreachable, Vercel will report `ImproperlyConfigured` rather than writing corrupt state. Fix the connection credentials or pooler host in Vercel Project Settings.
3. **Data Re-export:** The original SQLite file can be re-dumped at any time using Step 2.
