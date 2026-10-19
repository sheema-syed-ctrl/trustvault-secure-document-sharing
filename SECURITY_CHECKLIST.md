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
| **IDOR & Parameter Tampering** | Verified | Changing document UUID/ID in URL does not bypass server-side checks. Metadata forms reject ownership changes. |
| **Cross-Owner Isolation** | Verified | Owner A cannot view, edit, or delete Owner B's documents. Verified across all document endpoints. |

---

## 4. Operational Headers & Configuration

| Header / Setting | Configuration | Verification |
|------------------|---------------|--------------|
| `X-Frame-Options` | `DENY` | Prevents clickjacking framing. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing. |
| `SESSION_COOKIE_HTTPONLY` | `True` | Mitigates XSS-based session token exfiltration. |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Protects against cross-site request forgery. |
| `CSRF_COOKIE_SAMESITE` | `Lax` | Restricts CSRF token transmission on cross-site requests. |
