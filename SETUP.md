# TrustVault — Developer & Evaluator Setup Guide

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Tested Runtime:** Python 3.13.7 on Windows 11 & Linux Ubuntu 22.04 LTS

---

## 1. Prerequisites

Before installing TrustVault, ensure you have:
- **Python 3.13+** installed (`python --version` >= 3.13.0)
- **Git** installed
- **SQLite 3** (bundled with Python) or **PostgreSQL 14+** (for production)

---

## 2. Quick Setup (5 Minutes)

### Step 1: Clone or Navigate to the Repository
```bash
cd F:\Sheema
```

### Step 2: Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

On Linux / macOS (bash):
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the project root:
```env
DEBUG=True
SECRET_KEY=django-insecure-trustvault-local-dev-key-change-in-production
ALLOWED_HOSTS=127.0.0.1,localhost,[::1]
DB_ENGINE=sqlite
PROTECTED_MEDIA_DIR=protected_media
MAX_UPLOAD_SIZE_MB=25
```

### Step 5: Apply Migrations
```bash
python manage.py migrate
```

### Step 6: Seed Synthetic Demo Data
TrustVault provides an automated seeder that provisions demo accounts, sample documents, permissions, and audit logs:
```bash
python manage.py seed_demo_data --clean
```

> [!NOTE]
> Passwords are generated using Python's cryptographically secure `secrets` library and printed to your terminal. To provide explicit passwords instead, set environment variables before running:
> ```powershell
> $env:DEMO_ADMIN_PASSWORD="MyCustomAdminPass123!"
> $env:DEMO_OWNER_PASSWORD="MyCustomOwnerPass123!"
> $env:DEMO_VIEWER_PASSWORD="MyCustomViewerPass123!"
> python manage.py seed_demo_data --clean
> ```

Output account reference:
| Role | Username | Password Provisioning | Purpose |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin_demo` | *Output dynamically in terminal* | System monitoring, user management, global audit trail |
| **Document Owner**| `owner_demo` | *Output dynamically in terminal* | Upload documents, grant/update/revoke shares |
| **Viewer** | `viewer_demo`| *Output dynamically in terminal* | Access shared documents, download, view permissions |

### Step 7: Run the Development Server
```bash
python manage.py runserver
```
Visit `http://127.0.0.1:8000/` in your browser.

---

## 3. Verification & Automated Testing

### Run Complete Django Test Suite
```bash
python manage.py test
```
*Expected Result:* 277 tests passing (100% pass rate).

### Run Test Suite via Pytest
```bash
pytest
```

### Run Dedicated Security Test Suite
```bash
python manage.py test core.test_security
```
*Expected Result:* 36 dedicated security tests passing (~2.0s execution time).

### Run Security Static Analysis (Bandit)
```bash
bandit -r accounts documents permissions audit dashboard core trustvault -x "*/tests*,*/test_*"
```
*Expected Result:* 0 High, 0 Medium, 0 Low security issues.

### Run Dependency Vulnerability Audit (Pip-Audit)
```bash
pip-audit
```
*Expected Result:* No known vulnerabilities found.

### Test Health Check Endpoint
```bash
curl http://127.0.0.1:8000/health/
```
*Expected JSON Response:*
```json
{
  "status": "healthy",
  "database": "connected",
  "storage": "accessible",
  "version": "1.0.0"
}
```
