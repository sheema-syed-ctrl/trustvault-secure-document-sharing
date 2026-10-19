# TrustVault System Architecture

## Architectural Principles & Layered Design

TrustVault is built as a highly modular monolith following the principle of least privilege, defense-in-depth, and strict separation of concerns.

```
+-------------------------------------------------------------------------+
|                           Presentation Layer                            |
|    Bootstrap 5.3 Responsive Views, Role Dashboards, Accessible UI       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        Centralized Authorization                        |
|  Default-Deny Access Engine: can_view, can_download, can_edit, etc.     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        Application Service Layer                        |
|   Document Lifecycle, Binary Magic Byte Validation, Sharing & Revoke    |
+-------------------------------------------------------------------------+
                  |                                           |
                  v                                           v
+------------------------------------+      +-----------------------------+
|          Data Access Layer         |      |    Storage Security Layer   |
| Django ORM (PostgreSQL / SQLite)   |      | Segregated Protected Media  |
+------------------------------------+      +-----------------------------+
                  |
                  v
+-------------------------------------------------------------------------+
|                        Audit & Logging Subsystem                        |
|   Append-Only Activity Ledger, Context Enrichment (Actor, IP, Timestamp)|
+-------------------------------------------------------------------------+
```

### 1. Presentation Layer
- Standard server-side rendered Django templates using Bootstrap 5.3 with semantic HTML5.
- Centralized error pages (`400`, `403`, `404`, `500`) prevent information leakage (e.g., stack traces or internal filesystem structures are suppressed in production).
- CSRF-protected forms for all state-altering requests (including logout).

### 2. Authorization Layer (Zero-Trust)
- Server-side access checks are executed on every protected request.
- Client-side visibility flags (e.g. hiding a button) are never treated as security controls.
- Role-based capabilities:
  - **Administrator:** System configuration, user administration, global audit log viewing. *Crucially, does not have arbitrary read access to private document contents.*
  - **Document Owner:** Full authority over own documents (upload, edit, delete, grant permissions, revoke permissions).
  - **Viewer:** Access restricted to documents where an explicit `DocumentPermission` grant exists.

### 3. Storage Layer
- Private files are kept in `protected_media/`, strictly isolated from `STATIC_ROOT` and any public HTTP URL scheme.
- Serving files uses Django's streaming response after passing through authorization checks.
- Uploaded files are renamed using cryptographically secure UUIDs/hashes to prevent path traversal, filename collisions, and arbitrary execution.

### 4. Audit Trail Layer
- Security-relevant events (e.g., `LOGIN`, `LOGOUT`, `DOCUMENT_UPLOAD`, `DOCUMENT_VIEW`, `DOCUMENT_DOWNLOAD`, `PERMISSION_GRANTED`, `PERMISSION_REVOKED`, `ACCESS_DENIED`) are recorded in an append-only table.
- Logs capture actor, target document, action result, timestamp, client IP, and relevant metadata without logging sensitive document contents or credentials.
