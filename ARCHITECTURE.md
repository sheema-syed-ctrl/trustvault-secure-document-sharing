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

### 5. Document Management Engine & File Security Subsystem (Phase 03)
- **Zero-Trust File Ingestion:** All uploaded files pass through `documents/validators.py:validate_file_upload`.
  - Browser-supplied `Content-Type` headers and file extensions are treated as untrusted user input.
  - Initial binary chunks (4096 bytes) are inspected via `filetype` magic-byte signature matching.
  - Extension spoofing (e.g. executable `.exe` or script renamed as `.pdf`) triggers immediate validation failure.
  - Plain text files are verified against clean UTF-8 decoding without null-byte injections.
  - Strict file size cap is enforced at `settings.MAX_UPLOAD_SIZE_BYTES` (25 MB default).
- **Physical Storage Isolation:**
  - Files are written to `protected_media/<uuid4>.bin`, outside the web root and with no public URL routing.
  - Internal UUID filenames eliminate filename collisions and negate path traversal attacks.
  - Original filenames are sanitized using `sanitize_filename()` before saving as display metadata.
- **Atomic Operations & Safe Cleanup:**
  - Ingestion runs in database transaction blocks; failures automatically clean up written physical files.
  - Deletion via `DocumentService.delete_document()` destroys both the database record and physical disk file safely.
- **Cross-Owner Object Isolation:**
  - Document owners can manage only their own documents. Viewers and cross-owners attempting direct access to detail, edit, or delete endpoints receive HTTP 403 `PermissionDenied`.
