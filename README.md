# TrustVault — Secure Document Sharing with a Real Audit Trail

**Submission for Snovasys Fresher Hiring Challenge 2026**  
**Submission Deadline:** 25 October 2026, 6:00 PM IST  
**Primary Stack:** Python 3.13, Django 5.1, SQLite / PostgreSQL, Bootstrap 5.3, JavaScript

---

## 1. Project Overview

TrustVault is an enterprise-grade secure document-sharing platform engineered to satisfy rigorous corporate compliance, confidentiality, and data integrity standards. Unlike conventional file vaults, TrustVault implements:

1. **Explicit Role-Based Access Control (RBAC):** Three distinct personas (`Administrator`, `Document Owner`, and `Viewer`). Administrators govern user accounts and audit streams without having automatic eavesdropping access to private document contents.
2. **Object-Level Authorization Engine:** Document-level READ and EDIT permissions are independently granted and evaluated on every server request.
3. **Zero-Trust Private File Storage:** Files are stored in an unexposed server directory (`protected_media/`) and can never be downloaded or viewed via public static URLs.
4. **File Signature & Magic-Byte Verification:** Uploads are validated against actual binary content signatures rather than easily spoofed client-supplied MIME types and extensions.
5. **Real, Immutable Audit Trail:** Every sensitive operation (login, upload, view, download, edit, share, revocation, access denied) is permanently logged with timestamps, IP addresses, actor identities, and full context.
6. **Instant Revocation:** Permission revocation takes effect immediately; cached URLs or bookmarked links cannot bypass server-side checks.

---

## 2. Architecture & Application Structure

TrustVault follows a modular Django architecture with strict separation of concerns:

- `accounts/`: User identity, authentication, custom user model with strict roles (`ADMIN`, `OWNER`, `VIEWER`), and admin user management.
- `documents/`: Document lifecycle (upload, metadata management, binary file validation, deletion, and category indexing).
- `permissions/`: Object-level authorization service (`can_view`, `can_download`, `can_edit`, `can_delete`, `can_manage_access`) and sharing management.
- `audit/`: Append-only security audit trail recording all platform operations and denied access attempts.
- `dashboard/`: Role-specific dashboards tailored for Administrators, Document Owners, and Viewers.
- `core/`: Centralized HTTP error handling (400, 403, 404, 500), security decorators, shared utilities, and base layout.

---

## 3. Local Setup & Quickstart

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Git
- pip

### Installation Steps

1. **Clone the repository and enter directory:**
   ```bash
   git clone <repo-url>
   cd trustvault
   ```

2. **Create and activate virtual environment:**
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

5. **Run Database Migrations:**
   ```bash
   python manage.py makemigrations accounts
   python manage.py migrate
   ```

6. **Run Automated Tests:**
   ```bash
   python manage.py test
   ```

7. **Start Development Server:**
   ```bash
   python manage.py runserver
   ```
   Visit `http://127.0.0.1:8000/` in your browser.

---

## 4. Security Guarantees

- **No Public Media Exposure:** Document downloads are routed through an authenticated controller verifying permissions before streaming binary chunks.
- **CSRF & Clickjacking Protection:** All state-changing requests require valid CSRF tokens; `X-Frame-Options` is set to `DENY`.
- **Session Security:** `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`.
- **Privilege Escalation Prevention:** User role assignment is protected by server-side authorization; normal users cannot elevate their role.
