# TrustVault Security Verification Checklist

This living checklist tracks application security controls, verification evidence, and compliance status across TrustVault engineering phases.

---

## 1. Authentication & Identity Management (Phase 01–02)

| Control | Status | Evidence / Implementation |
|---------|--------|---------------------------|
| **Custom User Model** | Verified | `accounts.User` extending `AbstractUser` with explicit `Role` choices (`ADMIN`, `OWNER`, `VIEWER`). |
| **Password Validation** | Verified | Built-in validators enforce minimum length (8 chars), similarity, and common dictionary rejection. |
| **Privilege Escalation Prevention** | Verified | Public self-registration rejects `role=ADMIN` via `UserRegistrationForm.clean_role()`. Tested in `accounts.tests`. |
| **Admin Self-Protection** | Verified | `AdminUserUpdateForm` blocks administrators from self-demotion or self-deactivation. |
| **CSRF Defense on Logout** | Verified | `logout_view` decorated with `@require_POST` and enforces CSRF tokens. Rejects GET with HTTP 405. |
| **Session Fixation Defense** | Verified | `auth_login` cycles session key upon authentication. |
| **Open Redirect Defense** | Verified | `login_view` sanitizes `next` redirect parameter using `url_has_allowed_host_and_scheme`. |

---

## 2. Document Storage & Validation (Phase 03)

| Control | Status | Evidence / Implementation |
|---------|--------|---------------------------|
| **Private Media Storage** | Verified | Documents stored in `protected_media/` outside web root. No public `MEDIA_URL` exposed. |
| **Binary Signature Verification** | Verified | `documents.validators:validate_file_upload` inspects magic bytes (4096 bytes) via `filetype`. |
| **File Extension Whitelist** | Verified | Permitted extensions (.pdf, .png, .jpg, .jpeg, .txt, .docx, .doc) strictly mapped to verified MIME types. |
| **Extension Spoofing Defense** | Verified | Tested in `documents.tests:test_file_signature_spoofing_rejected` (rejects renamed executables/images). |
| **Path Traversal Defense** | Verified | User filenames sanitized via `sanitize_filename()`; disk filenames generated via `uuid.uuid4().hex + ".bin"`. |
| **Cryptographic Hashing** | Verified | SHA-256 digest computed during ingestion and stored with document metadata. |
| **File Upload Size Cap** | Verified | Uploads capped at `settings.MAX_UPLOAD_SIZE_BYTES` (25 MB default). Tested with oversized payloads. |
| **Safe Storage Cleanup** | Verified | `DocumentService.delete_document()` cleans up physical files from disk upon DB deletion. |

---

## 3. Document Permission Engine (Phase 04)

| Control | Status | Evidence / Implementation |
|---------|--------|---------------------------|
| **Default-Deny Access** | Verified | `PermissionService` denies all access unless explicit ownership or permission record exists. |
| **Granular Object Permissions** | Verified | Explicit `READ` and `EDIT` types defined in `permissions.DocumentPermission`. |
| **Permission Uniqueness** | Verified | Database `UniqueConstraint(fields=['document', 'user'])` blocks duplicate permission records. |
| **READ User Isolation** | Verified | READ grantees cannot edit, delete, or manage permissions. Direct access to `/edit/` or `/delete/` yields HTTP 403. |
| **EDIT User Isolation** | Verified | EDIT grantees can view and modify metadata. They cannot delete documents or manage permissions. |
| **Deletion Exclusivity** | Verified | Only the document owner can delete documents. |
| **Administrator Trust Boundary** | Verified | Administrators do **not** inherit access to private document contents. Tested in `permissions.tests`. |
| **Admin Panel Privilege Escalation Defense** | Verified | `DocumentPermissionAdmin` and `DocumentAdmin` set `has_add_permission=False`, `has_change_permission=False`, `has_delete_permission=False`. Admins cannot create permissions, modify permissions, or reassign document owners via Django Admin. |
| **Model-Level Grantor Validation** | Verified | `DocumentPermission.clean()` validates that `granted_by == document.owner`, preventing non-owners or admins from issuing unauthorized grants. |
| **Dual-State Deletion Consistency** | Verified | `DocumentService.delete_document()` guarantees database atomicity and triggers disk file removal via `transaction.on_commit()`, preventing file loss on DB rollback. |
| **IDOR & Parameter Tampering** | Verified | Changing document UUID/ID in URL does not bypass server-side checks. Metadata forms reject ownership changes. |
| **Cross-Owner Isolation** | Verified | Owner A cannot view, edit, or delete Owner B's documents. Verified across all document endpoints. |

---

## 4. Secure Document Access & Download Delivery (Phase 05)

| Control | Status | Evidence / Implementation |
|---------|--------|---------------------------|
| **Protected Download Broker** | Verified | All document downloads mediated through `/documents/<doc_id>/download/`. No public file endpoints exist. |
| **Download Authorization Matrix** | Verified | Enforced via `DocumentService.get_authorized_file()`: Owners, READ grantees, EDIT grantees permitted. Unassigned users (403), Admins without grant (403), Anonymous (302) denied. |
| **Path Traversal & Symlink Defense** | Verified | Verified with `is_relative_to(root)` in `get_protected_storage_path()`. Escaping paths raise `PermissionDenied`. |
| **Missing Storage File Safety** | Verified | Missing physical files return HTTP 404 without leaking internal system paths to users; logged at ERROR level. |
| **Content-Disposition Sanitization** | Verified | Original filename sanitized with `sanitize_filename()`, stripping CRLF (`\r`, `\n`) to prevent HTTP response splitting. |
| **Attachment Disposition Default** | Verified | `as_attachment=True` prevents browsers from inline executing untrusted or potentially active formats. |
| **Chunked File Streaming** | Verified | Streamed via `FileResponse` in chunks; memory footprint remains low for large files; handles auto-close. |
| **Private Cache Protection** | Verified | `Cache-Control: private, no-store, max-age=0, must-revalidate` and `Pragma: no-cache` prevent caching. |
| **HTTP Method Restriction** | Verified | Only `GET` and `HEAD` allowed (`@require_http_methods(['GET', 'HEAD'])`). Other verbs return HTTP 405. |

---

## 5. Operational Headers & Configuration

| Header / Setting | Configuration | Verification |
|------------------|---------------|--------------|
| `X-Frame-Options` | `DENY` | Prevents clickjacking framing. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing. |
| `SESSION_COOKIE_HTTPONLY` | `True` | Mitigates XSS-based session token exfiltration. |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Protects against cross-site request forgery. |
| `CSRF_COOKIE_SAMESITE` | `Lax` | Restricts CSRF token transmission on cross-site requests. |

---

## 6. Document Sharing & Revocation Security (Phase 06)

| Control | Status | Evidence / Implementation |
|---------|--------|---------------------------|
| **Owner-Only Sharing Authority** | Verified | Enforced via `PermissionService.can_manage_permissions()`. Viewers and admins receive HTTP 403. |
| **Self-Sharing Prevention** | Verified | `DocumentShareForm.clean_recipient_username()` and `PermissionService.grant_permission()` reject self-sharing with `ValidationError`. |
| **Inactive Account Protection** | Verified | Inactive accounts (`is_active=False`) are rejected during sharing and excluded from search results. |
| **Atomic Permission Grants** | Verified | Handled in `transaction.atomic()` via `update_or_create()`, preventing race conditions and duplicate rows. |
| **Cross-Document IDOR Protection** | Verified | Permission update and revoke endpoints validate `perm.document_id == document.id`, preventing cross-document manipulation. |
| **POST-Only State Alterations** | Verified | Grant, update, and revoke endpoints decorated with `@require_POST`. GET returns HTTP 405. |
| **CSRF Enforcement on Mutations** | Verified | All sharing forms enforce CSRF verification; requests lacking tokens are rejected with HTTP 403. |
| **Immediate Access Cutoff** | Verified | Revoked users immediately lose access to detail views, download streams, and edit endpoints. |
| **Document Preservation on Revoke** | Verified | Revoking permissions deletes `DocumentPermission` records only; underlying `Document` and files are preserved. |
| **Bounded Recipient Lookup** | Verified | User search API restricted to owners; queries capped at 20 results; returns only `id`, `username`, `role`. |

