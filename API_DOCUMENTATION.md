# TrustVault — REST & HTTP API Endpoint Documentation

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Security Standard:** OWASP ASVS Level 2, Zero-Trust Server-Side Authorization
**Protocol:** HTTP/1.1 & HTTP/2 over TLS

---

## 1. Overview & Architecture Principles

TrustVault is architected around a server-rendered modular Django monolith augmented with responsive UI and JSON endpoints for health, live user search, and statistics.

### Global Security Invariants
1. **Default-Deny Authorization:** Every request is authenticated and authorized at the view/service layer.
2. **CSRF Enforcement:** All state-changing operations (`POST`) strictly require a valid CSRF token.
3. **HTTP Strict Transport Security & Clickjacking Protection:** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
4. **Audit Trail Persistence & Immutability:** Every state change, authorization failure (HTTP 403), and file download triggers a database-backed `AuditEvent`. Audit records are strictly append-only, enforced at both the model instance and ORM `QuerySet` level (intercepting `.update()`, `.bulk_update()`, `.delete()`).
5. **Multi-Factor Rate Limiting:** High-frequency authentication attempts are throttled using cache-backed sliding windows (5 failed attempts per 300s window) returning HTTP 429 Too Many Requests.

---

## 2. Global Endpoint Directory

| App / Domain | Route Path | Method(s) | Auth Required | Role Required | CSRF | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **System** | `/health/` | `GET` | No | Any / Anonymous | No | Automated container orchestrator health probe |
| **Core** | `/` | `GET` | No | Any / Anonymous | No | Public landing page / dashboard redirect |
| **Auth** | `/accounts/register/` | `GET, POST` | No | Anonymous | Yes | Self-registration (Viewer or Owner role) |
| **Auth** | `/accounts/login/` | `GET, POST` | No | Anonymous | Yes | Session login with brute-force defense |
| **Auth** | `/accounts/logout/` | `POST` | Yes | Authenticated | Yes | Secure session invalidation |
| **Accounts**| `/accounts/users/` | `GET` | Yes | Administrator | No | User directory and role management index |
| **Accounts**| `/accounts/users/create/`| `GET, POST`| Yes | Administrator | Yes | Administrator-provisioned user creation |
| **Accounts**| `/accounts/users/<id>/` | `GET, POST`| Yes | Administrator | Yes | User role modification & account status |
| **Documents**| `/documents/` | `GET` | Yes | Authenticated | No | Accessible document directory & search |
| **Documents**| `/documents/upload/` | `GET, POST`| Yes | Document Owner | Yes | Secure file upload to protected vault |
| **Documents**| `/documents/<id>/` | `GET` | Yes | Owner / Grantee | No | Document detail view & metadata |
| **Documents**| `/documents/<id>/edit/`| `GET, POST`| Yes | Owner / EDIT Grantee | Yes | Metadata modification (Name, Description, Category) |
| **Documents**| `/documents/<id>/delete/`| `POST` | Yes | Document Owner | Yes | Atomic document deletion & physical file cleanup |
| **Documents**| `/documents/<id>/download/`| `GET, HEAD` | Yes | Owner / Grantee | No | Authenticated binary file streaming (FileResponse) |
| **Permissions**| `/permissions/document/<id>/` | `GET` | Yes | Document Owner | No | Active permissions management console |
| **Permissions**| `/permissions/document/<id>/grant/` | `POST` | Yes | Document Owner | Yes | Grant READ or EDIT permission to recipient |
| **Permissions**| `/permissions/document/<id>/update/<pid>/` | `POST` | Yes | Document Owner | Yes | Alter permission level (READ <-> EDIT) |
| **Permissions**| `/permissions/document/<id>/revoke/<pid>/` | `POST` | Yes | Document Owner | Yes | Immediate access revocation |
| **Permissions**| `/permissions/document/<id>/users/search/` | `GET` | Yes | Document Owner | No | AJAX user recipient autocomplete search |
| **Audit** | `/audit/` | `GET` | Yes | Administrator | No | Global immutable audit trail inspection |
| **Audit** | `/audit/document/<id>/` | `GET` | Yes | Document Owner | No | Per-document activity monitoring log |
| **Dashboard** | `/dashboard/` | `GET` | Yes | Authenticated | No | Role-specific workspace dispatch router |

---

## 3. Detailed Endpoint Specifications

### 3.1 Health Check Probe
- **Endpoint:** `GET /health/`
- **Authentication:** None (Publicly accessible to load balancers, AWS ALB, Render health checks).
- **Behavior:** Queries database (`SELECT 1;`) and tests protected media writability.
- **Success Response (200 OK):**
```json
{
  "status": "healthy",
  "database": "connected",
  "storage": "accessible",
  "version": "1.0.0"
}
```
- **Error Response (503 Service Unavailable):**
```json
{
  "status": "unhealthy",
  "database": "disconnected: Database connection timeout",
  "storage": "accessible",
  "version": "1.0.0"
}
```

---

### 3.2 Authentication & Rate-Limited Login
- **Endpoint:** `POST /accounts/login/`
- **Authentication:** Anonymous / Unauthenticated.
- **Headers:** `Content-Type: application/x-www-form-urlencoded`, `X-CSRFToken: <token>`
- **Parameters:**
  - `username`: string
  - `password`: string
- **Security & Rate Limiting Controls:**
  - Enforces `LoginRateLimitService`: Throttles brute force attacks across multi-factor composite keys (`sha256(ip + normalized_username)`).
  - Maximum 5 failed attempts per 300-second (5-minute) sliding window.
  - Uniform timing and generic error responses prevent username enumeration attacks.
  - Successful authentication clears the rate limit counter.
- **Success Response:** 302 Redirect to `/dashboard/` with session cookie.
- **Throttled Response (429 Too Many Requests):**
  - Renders login page with status code 429 and error: "Too many failed login attempts. Please try again in 5 minutes."
- **Failed Response (200 OK):**
  - Renders login page with generic credential failure notification.

---

### 3.3 Document Upload
- **Endpoint:** `POST /documents/upload/`
- **Authentication:** Required (User role must be `OWNER`).
- **Headers:** `Content-Type: multipart/form-data`, `X-CSRFToken: <token>`
- **Parameters:**
  - `name`: string (max 255 chars)
  - `description`: string (optional)
  - `category`: string (`TECHNICAL`, `LEGAL`, `FINANCIAL`, `CONFIDENTIAL`, `GENERAL`)
  - `document_file`: binary file (max 25 MB, permitted: PDF, PNG, JPEG, TXT, DOCX, DOC)
- **Validation Pipeline:**
  1. RBAC authorization gate (Owner role required; Viewers and Admins rejected with 403).
  2. Magic-byte signature verification via `filetype`.
  3. Filename path traversal sanitization.
  4. Cryptographic UUID storage filename assignment (`<uuid4>.bin`).
  5. Atomic file streaming and `AuditEvent` logging.
- **Success Response:** 302 Redirect to `/documents/<id>/`.
- **Error Response:** 400 Bad Request with form error messages.

---

### 3.4 Protected Document Download & Streaming
- **Endpoint:** `GET /documents/<id>/download/`
- **Authentication:** Required (Owner or active grantee with `READ` or `EDIT`).
- **Behavior:**
  - Server-side authorization check via `PermissionService.can_read()`.
  - Path traversal check confirming path resides within `PROTECTED_MEDIA_ROOT`.
  - Direct HTTP streaming via `FileResponse` with sanitized `Content-Disposition`.
  - Logs `DOCUMENT_DOWNLOADED` in persistent audit trail.
- **Response Headers:**
  - `Content-Type`: `application/pdf` (or corresponding MIME type)
  - `Content-Disposition`: `attachment; filename="document_spec.pdf"`
  - `X-Content-Type-Options`: `nosniff`
  - `X-Frame-Options`: `DENY`
- **Access Denied Response (403 Forbidden):**
  - Renders custom 403 error template.
  - Logs `SECURITY_ACCESS_DENIED` in audit trail.

---

### 3.5 Permission Granting & Revocation
- **Endpoint:** `POST /permissions/document/<id>/grant/`
- **Authentication:** Required (Document Owner only).
- **Parameters:**
  - `user_id`: integer (ID of recipient user)
  - `permission_type`: string (`READ` or `EDIT`)
- **Behavior:**
  - Atomically creates or updates `DocumentPermission`.
  - Immediately enables grantee access.
  - Logs `PERMISSION_GRANTED` audit event.
- **Success Response:** 302 Redirect to `/permissions/document/<id>/`.

- **Endpoint:** `POST /permissions/document/<id>/revoke/<pid>/`
- **Authentication:** Required (Document Owner only).
- **Behavior:**
  - Cross-document validation: Verifies `permission.document_id == id`.
  - Atomically deletes permission record.
  - Immediately terminates grantee access.
  - Logs `PERMISSION_REVOKED` audit event.
- **Success Response:** 302 Redirect to `/permissions/document/<id>/`.

---

### 3.6 Global Audit Trail & Immutability
- **Endpoint:** `GET /audit/`
- **Authentication:** Required (User role must be `ADMIN`).
- **Query Parameters:**
  - `event_type`: filter by `AuditEventType`
  - `status`: filter by `SUCCESS` or `FAILURE`
  - `q`: search by actor username or document name
  - `date_from`, `date_to`: ISO date range
- **Access Control:**
  - Document Owners and Viewers attempting to access `/audit/` receive HTTP 403 Forbidden.
  - Audit event logs are completely read-only; no modification or deletion endpoints exist.
  - Enforces ORM-level immutability (`AuditQuerySet` raises `ValidationError` on `update()`, `bulk_update()`, and `delete()`).
  - Automatically captures persistent `SECURITY_ACCESS_DENIED` events across document metadata inspection, edit attempts, delete requests, and unauthorized permission management attempts.

---

### 3.7 Role-Specific Dashboards
- **Endpoint:** `GET /dashboard/`
- **Authentication:** Required.
- **Dispatch Logic:**
  - `ADMIN`: Dispatches `admin_dashboard_view` (System metrics, total user count, total documents, failed security events, user administration link). Document download links are suppressed.
  - `OWNER`: Dispatches `owner_dashboard_view` (Storage utilization, owned documents list, active shares count, recent document events).
  - `VIEWER`: Dispatches `viewer_dashboard_view` (Shared documents partitioned into READ vs EDIT permissions, recent downloads).
