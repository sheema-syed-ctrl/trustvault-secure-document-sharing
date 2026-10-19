# TRUSTVAULT — PHASE 05 FINAL SECURITY ACCEPTANCE AUDIT
**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Phase:** 05 — Secure Document Access, Protected File Streaming & Download Authorization  
**Submission Deadline:** 25 October 2026, 6:00 PM IST  
**Audit Date:** 19 October 2026  
**Auditor:** Principal Django Engineer & Application Security Reviewer  
**Final Verdict:** **VERIFIED — ACCEPTED**  

---

## 1. UUID Routing Resolution

### 1.1 Document Primary Key vs UUID Field Analysis
An independent inspection of `documents/models.py`, `documents/urls.py`, `documents/views.py`, `documents/services.py`, and `documents/tests.py` establishes the following architectural reality:

```python
# documents/models.py
class Document(models.Model):
    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    ...
```

- **Actual Primary Key:** `id = models.BigAutoField(primary_key=True)`. The primary key of the `Document` model is an autoincrementing 64-bit integer (`BigAutoField`), established during Phase 03 in the initial migration `0001_initial.py`.
- **Secondary Cryptographic Identifier:** `uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)` is maintained as an indexed, unique secondary identifier for cryptographic correlation and internal asset isolation.
- **Physical Storage Filename:** Generated via `uuid.uuid4().hex + ".bin"` to ensure physical isolation on the filesystem outside the web root (`protected_media/<random_uuid>.bin`), preventing filename collisions and path traversal.

### 1.2 Routing Justification & Converter Clarification
The route definition in `documents/urls.py`:
```python
path('<int:doc_id>/download/', views.document_download_view, name='download'),
```
- **Converter Used:** `<int:doc_id>`. This converter precisely aligns with the model's actual primary key (`id = models.BigAutoField(primary_key=True)`).
- **Resolution of Previous UUID Statement:** Earlier documentation colloquially referenced "UUID document identifiers" because each document carries both an internal `uuid` field and random UUID-based disk filenames (`storage_filename`). However, the URL routing across the entire documents application (`detail`, `edit`, `delete`, `download`) consistently operates on the integer primary key (`doc_id`), querying `pk=doc_id`.
- **Malformed Input Defense:** Django's `<int:doc_id>` converter enforces a strict regex `[0-9]+` at the URL resolution layer. Any attempt to supply non-integer strings, arbitrary text, or UUID-formatted strings (e.g., `/documents/invalid-id/download/` or `/documents/c4b8b6c4-1234-5678-90ab-cdef12345678/download/`) is rejected immediately with an HTTP 404 (Page Not Found) by the URL dispatcher. It never executes view code, never triggers database queries, and never causes a 500 server error.
- **Verification Evidence:** `test_malformed_or_non_integer_doc_id_returns_404` and `test_nonexistent_document_id_returns_404` confirm that invalid identifiers cleanly return HTTP 404 without information disclosure.

---

## 2. HEAD Request Verification

The download endpoint was audited and tested under HTTP `HEAD` method requests (`@require_http_methods(["GET", "HEAD"])`).

### 2.1 Audit Results
1. **Status Code:** `200 OK` is returned for authorized users.
2. **Header Preservation:** All security and content headers are fully generated and preserved identically to a `GET` request:
   - `Content-Type: application/pdf` (or verified MIME type)
   - `Content-Disposition: attachment; filename="<sanitized_filename>"`
   - `X-Content-Type-Options: nosniff`
   - `Cache-Control: private, no-store, max-age=0, must-revalidate`
   - `Pragma: no-cache`
3. **Empty Body Guarantee:** Django's `FileResponse` suppresses the response streaming body on `HEAD` requests. `streaming_content` yields 0 bytes (`len(b''.join(res.streaming_content)) == 0`). Zero document content or sensitive bytes are leaked over the wire.
4. **File Handle Closure:** Django's `FileResponse` registers the opened binary file handle in `_resource_closers`. When the client completes reading headers or the response closes (`res.close()`), `res.closed` is `True` and the operating system file descriptor is cleanly closed.
5. **Verification Evidence:** `test_head_request_preserves_headers_and_suppresses_body` and `test_unsupported_http_methods_rejected`.

---

## 3. Header & MIME Security

The download endpoint enforces strict defense-in-depth header controls to prevent MIME-sniffing, browser execution of untrusted content, intermediate caching, and header injection.

| Response Header | Configured Value | Security Purpose & Defense Mechanism |
| :--- | :--- | :--- |
| **`Content-Type`** | Verified MIME type from `settings.PERMITTED_FILE_TYPES` (e.g., `application/pdf`, `image/png`) | Accurately identifies document format based on magic-byte inspection performed during upload. |
| **`Content-Type` (Fallback)** | `application/octet-stream` | If `document.mime_type` is missing, blank, or not in `settings.PERMITTED_FILE_TYPES`, it safely defaults to generic binary stream to prevent browsers from executing arbitrary or active markup. |
| **`Content-Disposition`** | `attachment; filename="<sanitized>"` | Forces the user agent to download the file rather than rendering it inline in the browser context (neutralizing stored XSS vectors). |
| **Filename Sanitization** | `sanitize_filename(original_filename)` | Strips directory traversal separators (`/`, `\`) and non-whitelisted characters. Strictly permits `[a-zA-Z0-9._- ]`. Eliminates carriage returns (`\r`) and newlines (`\n`), preventing HTTP response splitting and CRLF header injection. |
| **`X-Content-Type-Options`** | `nosniff` | Prohibits modern browsers from MIME-sniffing the payload away from the declared `Content-Type`. |
| **`Cache-Control`** | `private, no-store, max-age=0, must-revalidate` | Mandates that sensitive confidential vault files are never cached by shared proxies, CDNs, or local browser disk caches. |
| **`Pragma`** | `no-cache` | Legacy HTTP/1.0 backward-compatible cache prevention header. |
| **No Metadata Leakage** | Headers contain no internal paths, database IDs, storage filenames, or sensitive user tokens | Prevents operational metadata leakage. |

---

## 4. Authorization Matrix & Regression Verification

The download endpoint invokes centralized permission checking on **EVERY** request via:
`DocumentService.get_authorized_file(actor=request.user, document_id=doc_id)` which internally executes `PermissionService.can_read(actor, document)`.

| Role / Actor Scenario | Expected Outcome | Actual Outcome | Test Name | Result |
| :--- | :---: | :---: | :--- | :---: |
| **Document Owner** | Allow download (`200 OK`) | `200 OK` (Streamed) | `test_owner_can_download_own_document` | **PASS** |
| **User with Explicit READ** | Allow download (`200 OK`) | `200 OK` (Streamed) | `test_read_grantee_can_download_document` | **PASS** |
| **User with Explicit EDIT** | Allow download (`200 OK`) | `200 OK` (Streamed) | `test_edit_grantee_can_download_document` | **PASS** |
| **Unassigned Authenticated User** | Deny download (`403 Forbidden`) | `403 Forbidden` | `test_unassigned_user_cannot_download_document` | **PASS** |
| **Administrator (No Explicit Permission)** | Deny download (`403 Forbidden`) | `403 Forbidden` | `test_admin_without_explicit_permission_cannot_download_document` | **PASS** |
| **Anonymous User** | Redirect to login (`302 Redirect`) | `302 Found` | `test_anonymous_user_cannot_download_document` | **PASS** |
| **Cross-Owner Tampering (IDOR Attempt)** | Deny download (`403 Forbidden`) | `403 Forbidden` | `test_user_cannot_download_another_users_document_by_changing_id` | **PASS** |
| **Revoked Grantee (Immediate Effect)** | Deny download (`403 Forbidden`) | `403 Forbidden` | `test_permission_revocation_reflected_immediately` | **PASS** |
| **Non-Owner Permission Grantor** | Deny service grant (`PermissionDenied`) | `PermissionDenied` | `test_service_grant_permission_enforces_owner_authorization` | **PASS** |
| **Non-Owner Permission Revoker** | Deny service revoke (`PermissionDenied`) | `PermissionDenied` | `test_service_revoke_permission_enforces_owner_authorization` | **PASS** |
| **Missing Storage File** | Not Found (`404 Not Found`) | `404 Not Found` | `test_missing_physical_file_handled_safely` | **PASS** |
| **Path Traversal Storage Request** | Forbidden (`PermissionDenied`) | `PermissionDenied` | `test_path_traversal_in_storage_path_rejected` | **PASS** |
| **Unsupported Methods (POST/PUT/DELETE)** | Method Not Allowed (`405`) | `405 Method Not Allowed` | `test_unsupported_http_methods_rejected` | **PASS** |
| **HEAD Method Request** | Headers preserved, empty body (`200`) | `200 OK` (0 B body) | `test_head_request_preserves_headers_and_suppresses_body` | **PASS** |
| **Unrecognized MIME Fallback** | Fallback to binary stream (`200`) | `200 OK` (`octet-stream`) | `test_unrecognized_or_missing_mime_type_falls_back_to_octet_stream` | **PASS** |
| **Non-Integer doc_id Routing** | URL Pattern rejection (`404`) | `404 Not Found` | `test_malformed_or_non_integer_doc_id_returns_404` | **PASS** |

---

## 5. Verification Command Results

All five mandatory verification commands were executed in the project virtual environment (`Python 3.13.7`, `Django 5.2.18`).

### 5.1 System Check
```bash
> python manage.py check
System check identified no issues (0 silenced).
```
**Exit Code:** `0`

### 5.2 Makemigrations Dry-Run Check
```bash
> python manage.py makemigrations --check --dry-run
No changes detected
```
**Exit Code:** `0`

### 5.3 Migrate Status Check
```bash
> python manage.py migrate --check
```
**Exit Code:** `0` (All migrations up to date; zero pending schema alterations).

### 5.4 Django Test Suite (`manage.py test`)
```bash
> python manage.py test
Found 104 test(s).
System check identified no issues (0 silenced).
........................................................................................................
----------------------------------------------------------------------
Ran 104 tests in 385.810s

OK
Destroying test database for alias 'default'...
```
**Exit Code:** `0`

### 5.5 Pytest Suite (`pytest`)
```bash
> pytest
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.1.1, pluggy-1.7.0
django: version: 5.2.18, settings: trustvault.settings (from ini)
rootdir: F:\Sheema
configfile: pytest.ini
plugins: django-4.14.0
collected 104 items

accounts\tests.py ........................                               [ 23%]
core\tests.py ......                                                     [ 28%]
documents\tests.py ............................................          [ 71%]
permissions\tests.py ..............................                      [100%]

======================= 104 passed in 357.97s (0:05:57) =======================
```
**Exit Code:** `0`

---

## 6. Acceptance Verdict

### **VERDICT: VERIFIED — ACCEPTED**

1. **UUID Routing Resolution:** Fully resolved. Primary key is `BigAutoField` (`int`), URL converter `<int:doc_id>` is accurate and safe against parameter tampering, and non-integer inputs return clean 404s.
2. **HEAD Request Verification:** Fully verified. Returns 200 with identical security headers, strictly empty body (0 bytes), and file handles are safely closed.
3. **MIME & Header Security:** Fully verified. Content-Type correctly maps to verified MIME types with a strict fallback to `application/octet-stream` for unrecognized/missing types. Strict `nosniff`, `private, no-store`, and sanitized `attachment; filename=...` headers prevent cache poisoning and injection attacks.
4. **Authorization Integrity:** Centralized authorization via `PermissionService.can_read()` is verified on 100% of download attempts across all roles.
5. **Test Suite:** 104/104 tests passing across all four core applications (`accounts`, `core`, `documents`, `permissions`) with zero failures, zero errors, and zero warnings.

**Phase Boundary Notice:** No Phase 06 code has been introduced. Execution is paused awaiting user authorization for Phase 06 (Document Sharing).
