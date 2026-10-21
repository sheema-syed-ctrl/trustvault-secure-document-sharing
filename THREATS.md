# TrustVault Threat Model & Security Assessment (STRIDE)

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Evaluation Standard:** Microsoft STRIDE Threat Modeling Framework & OWASP Top 10
**Status:** **ACTIVE / VERIFIED**
**Last Updated:** 19 October 2026

---

## 1. Executive Threat Landscape & Methodology

TrustVault is a confidential document-sharing platform designed with a **Zero-Trust, Server-Side Authorization First** security architecture. Its primary objective is safeguarding sensitive enterprise documents against unauthorized access, data leakage, malicious tampering, and repudiation.

### Risk Rating Matrix
Risk levels are calculated using standard likelihood and impact dimensions:

| Severity | Definition | Policy Requirement |
|---|---|---|
| **CRITICAL** | System compromise, universal data breach, or unrestricted code execution. | Mandatory architectural blocker; immediate remediation. |
| **HIGH** | Cross-tenant document leakage, unauthorized privilege escalation, or audit evasion. | Mandatory blocker for production release. |
| **MEDIUM** | Partial information leakage, localized DoS, or credential brute-force risk. | Mitigated with defense-in-depth controls. |
| **LOW** | Minor information leakage or non-exploitable configuration deviation. | Addressed with security hardening guidelines. |

---

## 2. STRIDE Threat Inventory

```
+---------------------------------------------------------------------------------------------------------+
|                                        STRIDE THREAT OVERVIEW                                           |
+------------------------------------+-------------------------------------+------------------------------+
| S - Spoofing                       | T - Tampering                       | R - Repudiation              |
| - Account Impersonation            | - Document Metadata Modification    | - Unlogged Download Actions  |
| - Session Hijacking / Fixation     | - Cross-Document Permission IDOR    | - Audit Log Modification     |
| - Admin Role Injection             | - Physical File Tampering           | - Audit Event Deletion       |
+------------------------------------+-------------------------------------+------------------------------+
| I - Information Disclosure         | D - Denial of Service               | E - Elevation of Privilege   |
| - IDOR on Private File Streaming   | - Oversized Upload Resource Exhaust | - Admin Implicit Access      |
| - Search Metadata Leakage          | - Malformed Archive Decompression   | - Viewer-to-Owner Escalation |
| - Path Traversal / Symlink Escape  | - ReDoS / Query Parameter Abuse     | - Django Admin Direct Bypass |
+------------------------------------+-------------------------------------+------------------------------+
```

---

### S — Spoofing (Identity & Authentication)

#### `THREAT-S01`: Public Self-Registration Administrator Role Injection
- **STRIDE Category:** Spoofing / Elevation of Privilege
- **Affected Component:** `accounts.forms.UserRegistrationForm`, `accounts.views.register_view`
- **Attack Scenario:** Attacker intercepts the public registration POST request and modifies the `role` payload from `VIEWER` or `OWNER` to `ADMIN` (`role=ADMIN`).
- **Preconditions:** Unauthenticated attacker accessing public self-registration.
- **Impact:** Critical — Complete platform takeover with administrative governance privileges.
- **Likelihood:** High (common web vulnerability).
- **Severity:** **CRITICAL**
- **Existing Mitigation:** `UserRegistrationForm.clean_role()` explicitly rejects `role=ADMIN` submitted via public registration and raises a `ValidationError`. Role choices for self-registration are strictly limited to `OWNER` and `VIEWER`.
- **Additional Mitigation:** Server-side fallback defaults to `VIEWER` if tampering is detected.
- **Verification Test:** `accounts.tests.UserRegistrationTests.test_registration_blocks_admin_role_escalation`, `core.test_security.AuthenticationSecurityTests.test_registration_prevents_admin_role_injection`.
- **Residual Risk:** Low.

#### `THREAT-S02`: Session Fixation & Hijacking on Authentication
- **STRIDE Category:** Spoofing
- **Affected Component:** `accounts.views.login_view`, Django Session Framework
- **Attack Scenario:** Attacker pre-provisions an unauthenticated session identifier or intercepts an insecure session cookie over unencrypted HTTP, impersonating the user upon login.
- **Preconditions:** Network eavesdropping or victim clicking a crafted link with a pre-set session ID.
- **Impact:** High — Attacker gains full authenticated access to victim's workspace and documents.
- **Likelihood:** Medium.
- **Severity:** **HIGH**
- **Existing Mitigation:** `django.contrib.auth.login()` automatically cycles the session key upon authentication (`request.session.cycle_key()`). Session cookies configured with `HttpOnly=True`, `SameSite='Lax'`, and production flags enforce `Secure=True` under SSL.
- **Additional Mitigation:** Idle session timeout capped at 4 hours (`SESSION_COOKIE_AGE = 14400`) and refreshed on request (`SESSION_SAVE_EVERY_REQUEST = True`).
- **Verification Test:** `accounts.tests.AuthenticationTests.test_login_cycles_session_key`, `core.test_security.WebSecurityDefensesTests.test_security_headers_present`.
- **Residual Risk:** Low.

#### `THREAT-S03`: Open Redirect via Login `next` Parameter
- **STRIDE Category:** Spoofing
- **Affected Component:** `accounts.views.login_view`
- **Attack Scenario:** Attacker crafts a phishing link: `https://trustvault.local/accounts/login/?next=https://attacker-vault.com/steal`. After logging in, user is redirected to the external credential-harvesting page.
- **Preconditions:** Victim clicks malicious link with arbitrary `next` target.
- **Impact:** Medium — Credential theft or malware delivery.
- **Likelihood:** Medium.
- **Severity:** **MEDIUM**
- **Existing Mitigation:** `login_view` uses `django.utils.http.url_has_allowed_host_and_scheme(url=redirect_to, allowed_hosts={request.get_host()})`. Any external URL or protocol-relative target (`//evil.com`) is rejected and redirected safely to `dashboard:index`.
- **Additional Mitigation:** Strict whitelist verification against allowed hosts in `settings.ALLOWED_HOSTS`.
- **Verification Test:** `accounts.tests.AuthenticationTests.test_login_redirect_sanitization`, `core.test_security.AuthenticationSecurityTests.test_open_redirect_protection_on_login`.
- **Residual Risk:** Low.

---

### T — Tampering (Data Integrity)

#### `THREAT-T01`: Cross-Document Permission ID Manipulation (IDOR on Permissions)
- **STRIDE Category:** Tampering / Elevation of Privilege
- **Affected Component:** `permissions.views.document_permission_update_view`, `document_permission_revoke_view`
- **Attack Scenario:** Attacker (Owner Alice) has legitimate permission ID 10 on her Document A. Bob has permission ID 20 on Document B. Alice submits a POST request to `/permissions/document/<DocA_id>/update/<Perm20_id>/`, attempting to alter Bob's permission record.
- **Preconditions:** Authenticated Document Owner attempting cross-document manipulation.
- **Impact:** High — Unauthorized tampering with access control lists on unowned documents.
- **Likelihood:** High.
- **Severity:** **HIGH**
- **Existing Mitigation:** Views validate `perm.document_id == document.id`. If a mismatch is detected, a security warning is logged and an immediate HTTP 403 `PermissionDenied` is returned.
- **Additional Mitigation:** Database lookup strictly filters on both keys: `DocumentPermission.objects.filter(pk=perm_id, document=document)`.
- **Verification Test:** `permissions.tests.SharingWorkflowTests.test_15_cross_document_permission_id_manipulation_is_rejected`, `core.test_security.IDORAndCrossUserIsolationTests.test_cross_document_permission_idor_rejected`.
- **Residual Risk:** Low.

#### `THREAT-T02`: Physical File Path Traversal & Symlink Escape
- **STRIDE Category:** Tampering / Information Disclosure
- **Affected Component:** `documents.validators.sanitize_filename`, `documents.services.DocumentService.get_protected_storage_path`
- **Attack Scenario:** Attacker uploads a document with filename `../../../../etc/shadow.pdf` or `..\\windows\\system32\\cmd.exe.pdf`, attempting to overwrite critical operating system files or write outside the protected media root.
- **Preconditions:** Authenticated Document Owner uploading a file.
- **Impact:** Critical — Arbitrary file write, host compromise, or data corruption.
- **Likelihood:** Medium.
- **Severity:** **CRITICAL**
- **Existing Mitigation:**
  1. `sanitize_filename()` strips all path separators (`/`, `\`) and traversal sequences.
  2. Physical disk files are never named using user input; they are assigned random UUIDs: `uuid.uuid4().hex + ".bin"`.
  3. `get_protected_storage_path()` strictly enforces `target.is_relative_to(PROTECTED_MEDIA_ROOT.resolve())`.
- **Additional Mitigation:** Storage directory permissions restrict executable execution.
- **Verification Test:** `documents.tests.DocumentStorageSecurityTests.test_path_traversal_filename_sanitized`, `core.test_security.FileValidationAndStorageSecurityTests.test_path_traversal_in_filename_sanitized`.
- **Residual Risk:** Low.

#### `THREAT-T03`: Audit Trail Record Tampering or Alteration
- **STRIDE Category:** Tampering / Repudiation
- **Affected Component:** `audit.models.AuditEvent`
- **Attack Scenario:** Malicious insider or compromised account modifies existing `AuditEvent` records via ORM or application interface to alter timestamps, actor usernames, or event types.
- **Preconditions:** Code execution within application context.
- **Impact:** High — Loss of evidentiary audit integrity, invalid compliance posture.
- **Likelihood:** Low to Medium.
- **Severity:** **HIGH**
- **Existing Mitigation:** `AuditEvent.save()` overrides model save logic: if `self.pk is not None` (existing record), it unconditionally raises `ValidationError("AuditEvent records are append-only and cannot be modified.")`.
- **Additional Mitigation:** Django Admin disables all edit/change permissions on `AuditEventAdmin`.
- **Verification Test:** `audit.tests.AuditTrailTamperResistanceTests.test_audit_event_cannot_be_modified`, `core.test_security.AuditTrailIntegritySecurityTests.test_audit_event_is_append_only`.
- **Residual Risk:** Low.

---

### R — Repudiation (Accountability & Non-Repudiation)

#### `THREAT-R01`: Document Deletion Repudiation & Missing Target Snapshots
- **STRIDE Category:** Repudiation
- **Affected Component:** `audit.models.AuditEvent`, `documents.services.DocumentService.delete_document`
- **Attack Scenario:** User deletes a document and claims they never uploaded it, or subsequent deletion of a `User` cascades and blanks out audit actor names, leaving orphan logs with `actor=NULL` and `target_document=NULL`.
- **Preconditions:** Document owner deletes sensitive document or administrator deletes user.
- **Impact:** High — Unattributable data destruction or compliance failure.
- **Likelihood:** Medium.
- **Severity:** **HIGH**
- **Existing Mitigation:** `AuditEvent` stores permanent historical snapshots: `actor_username`, `target_document_id_snapshot`, `target_document_name_snapshot`, and `target_username_snapshot`. Even when foreign keys are deleted (`on_delete=models.SET_NULL`), snapshot fields remain intact in perpetuity.
- **Additional Mitigation:** Every document deletion records a `DOCUMENT_DELETED` audit event with filename and ID before disk unlinking.
- **Verification Test:** `audit.tests.AuditTrailLifecycleTests.test_document_deletion_preserves_historical_snapshots`, `core.test_security.AuditTrailIntegritySecurityTests.test_document_deletion_preserves_historical_snapshot`.
- **Residual Risk:** Low.

#### `THREAT-R02`: Audit Event Deletion / Clearing
- **STRIDE Category:** Repudiation
- **Affected Component:** `audit.models.AuditEvent`
- **Attack Scenario:** An actor attempts to delete incriminating audit records using `.delete()` or via an admin interface.
- **Preconditions:** Access to Django ORM or Admin panel.
- **Impact:** Critical — Complete destruction of forensic evidence.
- **Likelihood:** Medium.
- **Severity:** **CRITICAL**
- **Existing Mitigation:** `AuditEvent.delete()` explicitly raises `ValidationError("AuditEvent records cannot be deleted. The audit trail is immutable.")`. `AuditEventAdmin` sets `has_delete_permission = False` and `has_add_permission = False`.
- **Additional Mitigation:** Database-level append-only constraints or write-once logging.
- **Verification Test:** `audit.tests.AuditTrailTamperResistanceTests.test_audit_event_cannot_be_deleted`, `core.test_security.AuditTrailIntegritySecurityTests.test_audit_event_cannot_be_deleted`.
- **Residual Risk:** Low.

---

### I — Information Disclosure (Confidentiality)

#### `THREAT-I01`: IDOR on Direct Document Download Stream
- **STRIDE Category:** Information Disclosure
- **Affected Component:** `documents.views.document_download_view`, `documents.services.DocumentService.get_authorized_file`
- **Attack Scenario:** Attacker (Viewer Carla) is authorized on Document 1. She discovers URL pattern `/documents/<doc_id>/download/` and requests `/documents/2/download/`, attempting to stream Owner Bob's confidential blueprints.
- **Preconditions:** Authenticated user with network access to download endpoint.
- **Impact:** Critical — Direct breach of private enterprise documents.
- **Likelihood:** High (standard IDOR attack).
- **Severity:** **CRITICAL**
- **Existing Mitigation:** Download endpoint never streams files based on URL parameters alone. `DocumentService.get_authorized_file()` delegates object-level authorization to `PermissionService.can_read(actor, document)`. If unauthorized, it logs `SECURITY_ACCESS_DENIED` and raises HTTP 403 `PermissionDenied`.
- **Additional Mitigation:** Files are streamed in chunks (`FileResponse`) with headers `Cache-Control: private, no-store, max-age=0, must-revalidate` to prevent intermediary proxy caching.
- **Verification Test:** `documents.tests.DocumentDownloadSecurityTests.test_unauthorized_user_cannot_download`, `core.test_security.IDORAndCrossUserIsolationTests.test_cross_owner_download_access_forbidden`.
- **Residual Risk:** Low.

#### `THREAT-I02`: Search Index & Metadata Side-Channel Leakage
- **STRIDE Category:** Information Disclosure
- **Affected Component:** `documents.views.document_list_view`, `documents.services.DocumentService.search_documents`
- **Attack Scenario:** Viewer searches for `"Merger"` or `"Confidential"`. If search executes against global `Document.objects.all()`, private document titles, descriptions, and categories owned by other users are disclosed in search results.
- **Preconditions:** Authenticated Viewer performing search queries.
- **Impact:** High — Unauthorized disclosure of confidential business metadata.
- **Likelihood:** High.
- **Severity:** **HIGH**
- **Existing Mitigation:** Search queries are strictly applied to the user's pre-filtered authorization base queryset: `PermissionService.get_accessible_documents(user)`. Unauthorized documents are excluded at the database SQL query level (`owner=user OR id__in=accessible_ids`).
- **Additional Mitigation:** Total result counters and pagination metrics reflect only authorized items.
- **Verification Test:** `documents.tests.DocumentSearchSecurityTests.test_search_never_returns_unauthorized_documents`, `core.test_security.SearchAndDashboardScopingSecurityTests.test_search_results_strictly_scoped_to_authorized_documents`.
- **Residual Risk:** Low.

#### `THREAT-I03`: Sensitive Credential & Path Leakage in Audit Metadata
- **STRIDE Category:** Information Disclosure
- **Affected Component:** `audit.services.AuditService.sanitize_metadata`
- **Attack Scenario:** Application logs request payloads containing user passwords, session tokens, or local physical drive paths (e.g., `F:\Sheema\protected_media\...`). If audit records are viewed, confidential data is exposed to administrators.
- **Preconditions:** User performing authentication, sharing, or upload actions.
- **Impact:** High — Credential harvesting and infrastructure reconnaissance.
- **Likelihood:** High.
- **Severity:** **HIGH**
- **Existing Mitigation:** `AuditService.sanitize_metadata()` recursively inspects metadata dictionaries, stripping blacklisted sensitive keys (`password`, `token`, `session_id`, `csrftoken`, `cookie`, `file_path`, etc.) and redacting values containing local drive letters or system directory indicators (`f:\`, `c:\`, `/var/`, `/tmp/`).
- **Additional Mitigation:** Unit test explicitly asserts dirty metadata payloads are thoroughly sanitized.
- **Verification Test:** `audit.tests.AuditTrailSanitizationTests.test_metadata_deep_sanitization`, `core.test_security.AuditTrailIntegritySecurityTests.test_audit_metadata_deep_sanitization`.
- **Residual Risk:** Low.

---

### D — Denial of Service (Availability)

#### `THREAT-D01`: Oversized Payload & Storage Exhaustion
- **STRIDE Category:** Denial of Service
- **Affected Component:** `documents.validators.validate_file_upload`, `trustvault.settings.MAX_UPLOAD_SIZE_BYTES`
- **Attack Scenario:** Attacker uploads a multi-gigabyte file or streams continuous data, attempting to exhaust disk storage, overwhelm server memory, or crash the process.
- **Preconditions:** Authenticated Document Owner uploading files.
- **Impact:** High — Disk saturation, server crash, denial of service for all users.
- **Likelihood:** Medium.
- **Severity:** **HIGH**
- **Existing Mitigation:** `MAX_UPLOAD_SIZE_BYTES` defaults to 25 MB. `validate_file_upload` inspects `uploaded_file.size` before reading content. Files exceeding the cap are rejected with `ValidationError` and discarded before writing to disk.
- **Additional Mitigation:** Web server (Nginx/Gunicorn) `client_max_body_size` enforcement.
- **Verification Test:** `documents.tests.DocumentUploadSecurityTests.test_oversized_file_rejected`, `core.test_security.FileValidationAndStorageSecurityTests.test_disallowed_extension_rejected`.
- **Residual Risk:** Low.

#### `THREAT-D02`: Binary Magic-Byte Signature Spoofing (Polyglot / Trojan Uploads)
- **STRIDE Category:** Denial of Service / Remote Code Execution
- **Affected Component:** `documents.validators.validate_file_upload`
- **Attack Scenario:** Attacker uploads a malicious executable or shell script renamed with a permitted extension (e.g., `payload.exe` renamed to `payload.pdf`). If server relies only on file extension, malicious files could be stored and served.
- **Preconditions:** Authenticated Document Owner uploading files.
- **Impact:** High — Malware distribution, storage pollution.
- **Likelihood:** High.
- **Severity:** **HIGH**
- **Existing Mitigation:** `validate_file_upload()` inspects the first 4096 bytes using `filetype.guess()`. The detected MIME signature is validated against `PERMITTED_FILE_TYPES`. If extension and magic bytes disagree, a `Security Alert: Signature mismatch detected` error is raised. Plain text files (.txt) are verified to decode cleanly without binary null bytes (`\x00`).
- **Additional Mitigation:** Files are stored with `.bin` extensions, preventing direct execution by the operating system.
- **Verification Test:** `documents.tests.DocumentUploadSecurityTests.test_file_signature_spoofing_rejected`, `core.test_security.FileValidationAndStorageSecurityTests.test_mime_spoofing_magic_bytes_mismatch_rejected`.
- **Residual Risk:** Low.

---

### E — Elevation of Privilege (Authorization & Access Boundaries)

#### `THREAT-E01`: Viewer-to-Owner Privilege Escalation (Unauthorized Delete or Share)
- **STRIDE Category:** Elevation of Privilege
- **Affected Component:** `documents.views.document_delete_view`, `permissions.views.document_share_manage_view`
- **Attack Scenario:** Viewer Charlie holding `EDIT` permission attempts to delete Document 1 (`POST /documents/1/delete/`) or grant access to Viewer David (`POST /permissions/document/1/grant/`).
- **Preconditions:** Authenticated Viewer holding `EDIT` permission on a document.
- **Impact:** Critical — Destruction of owner documents, unauthorized privilege delegation.
- **Likelihood:** High.
- **Severity:** **CRITICAL**
- **Existing Mitigation:** Server views strictly enforce `PermissionService.can_delete()` and `PermissionService.can_manage_permissions()`. Both methods evaluate `document.owner_id == user.pk`. Non-owners receive HTTP 403 `PermissionDenied`. UI templates omit Delete and Share buttons for viewers.
- **Additional Mitigation:** Service-layer validation in `DocumentService.delete_document()` and `PermissionService.grant_permission()`.
- **Verification Test:** `dashboard.tests.ViewerDashboardTests.test_viewer_with_edit_permission_cannot_delete_share_or_manage_permissions`, `core.test_security.PermissionHierarchySecurityTests.test_edit_grantee_cannot_delete_or_manage_permissions`.
- **Residual Risk:** Low.

#### `THREAT-E02`: Administrator Implicit Document Access (Superuser Confusion)
- **STRIDE Category:** Elevation of Privilege / Information Disclosure
- **Affected Component:** `dashboard.views.admin_dashboard_view`, `permissions.services.PermissionService`
- **Attack Scenario:** System Administrator assumes they inherently possess download access to all private documents in the vault, or the admin dashboard renders download links for all documents.
- **Preconditions:** Authenticated user with `role=ADMIN`.
- **Impact:** Critical — Violation of the core TrustVault security model (governance vs content separation).
- **Likelihood:** Medium.
- **Severity:** **CRITICAL**
- **Existing Mitigation:** `PermissionService.can_read()` does **not** grant access based on `user.is_admin_role`. Administrators receive HTTP 403 if they attempt to download or view a document without an explicit owner grant. `admin_dashboard.html` displays system metrics and audit feeds, but **zero** download links.
- **Additional Mitigation:** `DocumentAdmin` in Django Admin sets `has_add_permission=False`, `has_change_permission=False`, `has_delete_permission=False`.
- **Verification Test:** `permissions.tests.PermissionEngineTests.test_admin_cannot_read_document_without_permission`, `dashboard.tests.AdminDashboardTests.test_admin_dashboard_never_leaks_download_links`, `core.test_security.PermissionHierarchySecurityTests.test_administrator_without_explicit_permission_denied_file_access`.
- **Residual Risk:** Low.

---

## 3. Summary of STRIDE Threats & Residual Risks

| Threat ID | STRIDE Category | Component | Severity | Mitigation Status | Residual Risk |
|---|---|---|---|---|---|
| `THREAT-S01` | Spoofing | Registration Form | **CRITICAL** | Form clean validation rejects ADMIN | Low |
| `THREAT-S02` | Spoofing | Session Framework | **HIGH** | Session rotation, HttpOnly, SameSite, Secure | Low |
| `THREAT-S03` | Spoofing | Login View | **MEDIUM** | `url_has_allowed_host_and_scheme` check | Low |
| `THREAT-T01` | Tampering | Permission Views | **HIGH** | Compound document-permission validation | Low |
| `THREAT-T02` | Tampering | File Upload Service | **CRITICAL** | UUID filenames, path traversal sanitization | Low |
| `THREAT-T03` | Tampering | Audit Model | **HIGH** | Append-only model `.save()` override | Low |
| `THREAT-R01` | Repudiation | Document Service | **HIGH** | Historical audit snapshots on deletion | Low |
| `THREAT-R02` | Repudiation | Audit Model | **CRITICAL** | `.delete()` raises ValidationError | Low |
| `THREAT-I01` | Information Disclosure | Download Service | **CRITICAL** | Server-side `PermissionService.can_read()` | Low |
| `THREAT-I02` | Information Disclosure | Search Service | **HIGH** | Base queryset pre-filtered to accessible docs | Low |
| `THREAT-I03` | Information Disclosure | Audit Logging | **HIGH** | Recursive metadata & path sanitization | Low |
| `THREAT-D01` | Denial of Service | Upload Validator | **HIGH** | 25 MB size cap before disk write | Low |
| `THREAT-D02` | Denial of Service | Upload Validator | **HIGH** | Binary magic-byte signature inspection | Low |
| `THREAT-E01` | Elevation of Privilege | Delete/Share Views | **CRITICAL** | Strict owner-only checks on delete & share | Low |

---

### Sprint 1 Security Remediation Threats (TV-SEC-001 through TV-SEC-004)

#### `THREAT-R03`: Omission of Metadata Access Denial Audit Records (`TV-SEC-001`)
- **STRIDE Category:** Repudiation / Audit Evasion
- **Affected Component:** `documents.views` (`document_detail_view`, `document_edit_view`, `document_delete_view`), `permissions.views` (`document_share_manage_view`)
- **Attack Scenario:** An unauthorized user (Viewer or stranger) attempts to probe document metadata, submit unauthorized metadata edits, delete documents, or view permission lists. While the request is rejected with HTTP 403, if the denial is not persisted to the database audit trail, administrators and SIEM monitors cannot detect targeted reconnaissance.
- **Preconditions:** Authenticated user attempting unauthorized metadata access.
- **Impact:** Medium — Evasion of security event auditing; impaired incident response visibility.
- **Likelihood:** High.
- **Severity:** **MEDIUM**
- **Existing Mitigation:** Application views unconditionally raise `PermissionDenied` (HTTP 403) and log warnings to Python `django.security` logger.
- **Additional Mitigation (Sprint 1):** Explicitly wrapped authorization rejections with `AuditService.log_access_denied(actor=request.user, event_type=..., document=document, metadata={'attempted_action': ...})` across all metadata, edit, delete, and permission endpoints. Audit failures are handled gracefully without failing open.
- **Verification Test:** `audit.tests.PersistentAuditTrailEngineTests.test_33_unauthorized_metadata_view_creates_audit_denial_record`, `test_34_unauthorized_edit_attempt_creates_audit_denial_record`, `test_35_unauthorized_delete_attempt_creates_audit_denial_record`, `test_36_unauthorized_permission_manage_creates_audit_denial_record`.
- **Residual Risk:** Low.

#### `THREAT-S04`: Automated Credential Stuffing & High-Frequency Brute-Force (`TV-SEC-002`)
- **STRIDE Category:** Spoofing / Denial of Service
- **Affected Component:** `accounts.views.login_view`, `accounts.services.LoginRateLimitService`
- **Attack Scenario:** An automated adversary submits thousands of rapid password guesses or credential stuffing pairs against `/accounts/login/` without application throttling.
- **Preconditions:** Attacker with network access to authentication endpoint.
- **Impact:** Low to Medium — Account compromise via password guessing; CPU exhaustion from PBKDF2 hashing.
- **Likelihood:** High.
- **Severity:** **LOW**
- **Existing Mitigation:** Strong PBKDF2 SHA-256 password hashing with 390,000 iterations.
- **Additional Mitigation (Sprint 1):** Implemented `LoginRateLimitService` with multi-factor keying (IP + normalized username), throttling clients after 5 failed attempts within 300 seconds (HTTP 429). Applies uniform response timing to mitigate user enumeration. Counters reset upon successful login.
- **Verification Test:** `accounts.tests.LoginRateLimitingTests.test_repeated_login_failures_trigger_rate_limit`, `test_login_rate_limit_cleared_on_successful_login`, `test_login_rate_limit_does_not_reveal_user_existence`.
- **Residual Risk:** Low (edge botnets mitigated via upstream Cloudflare / WAF).

#### `THREAT-T04`: Audit Event ORM Bulk Mutation Bypass (`TV-SEC-003`)
- **STRIDE Category:** Tampering / Repudiation
- **Affected Component:** `audit.models.AuditEvent`, `audit.models.AuditQuerySet`, `audit.models.AuditManager`
- **Attack Scenario:** An internal attacker or malicious administrative script executes Django ORM bulk queries (e.g. `AuditEvent.objects.filter(...).delete()` or `.update(status='SUCCESS')`), bypassing instance-level `save()` and `delete()` overrides.
- **Preconditions:** Internal execution access within Django runtime or management shell.
- **Impact:** High — Tampering with historical audit evidence at the ORM layer.
- **Likelihood:** Low.
- **Severity:** **LOW**
- **Existing Mitigation:** Instance-level `save()` and `delete()` methods raise `ValidationError`. Django Admin denies add/change/delete permissions.
- **Additional Mitigation (Sprint 1):** Defined `AuditQuerySet` and `AuditManager` on `AuditEvent` overriding `.update()`, `.bulk_update()`, and `.delete()` to unconditionally raise `ValidationError("AuditEvent records are append-only and cannot be modified via bulk operations.")`.
- **Verification Test:** `audit.tests.PersistentAuditTrailEngineTests.test_37_audit_event_bulk_queryset_delete_blocked`, `test_38_audit_event_bulk_queryset_update_blocked`, `test_39_audit_event_manager_bulk_update_blocked`.
- **Residual Risk:** Low (direct raw SQL via DB superuser restricted by PostgreSQL database role permissions).

#### `THREAT-D03`: Ephemeral Container Storage Document Loss Upon Service Restart (`TV-SEC-004`)
- **STRIDE Category:** Denial of Service / Availability
- **Affected Component:** `trustvault.settings.PROTECTED_MEDIA_ROOT`, `render.yaml`
- **Attack Scenario:** A container restart, auto-scaling event, or deployment redeploy purges locally stored files on an ephemeral filesystem, corrupting document availability while leaving orphaned database records.
- **Preconditions:** Application hosted on standard PaaS container without persistent disk attachment.
- **Impact:** Medium — Data unavailability; valid document downloads fail with HTTP 404.
- **Likelihood:** High on free-tier container hosting.
- **Severity:** **INFORMATIONAL / ARCHITECTURAL**
- **Existing Mitigation:** Files are stored in private `PROTECTED_MEDIA_ROOT` outside public web serving.
- **Additional Mitigation (Sprint 1):** Updated `PROTECTED_MEDIA_ROOT` to resolve absolute storage mount paths. Configured Render Blueprint with persistent disk volume (`disk: name: trustvault-storage, mountPath: /var/data/trustvault_storage, sizeGB: 10`). Documented hosting requirement for paid Starter tier on Render.
- **Verification Test:** Settings resolution verification; storage health check probe (`/health/`).
- **Residual Risk:** Low on paid persistent disk; documented requirement for deployers.

---

## 3. Summary of STRIDE Threats & Residual Risks

| Threat ID | STRIDE Category | Component | Severity | Mitigation Status | Residual Risk |
|---|---|---|---|---|---|
| `THREAT-S01` | Spoofing | Registration Form | **CRITICAL** | Form clean validation rejects ADMIN | Low |
| `THREAT-S02` | Spoofing | Session Framework | **HIGH** | Session rotation, HttpOnly, SameSite, Secure | Low |
| `THREAT-S03` | Spoofing | Login View | **MEDIUM** | `url_has_allowed_host_and_scheme` check | Low |
| `THREAT-S04` | Spoofing | Login Rate Limiter | **LOW** | 5-attempt/300s multi-factor throttling (HTTP 429) | Low |
| `THREAT-T01` | Tampering | Permission Views | **HIGH** | Compound document-permission validation | Low |
| `THREAT-T02` | Tampering | File Upload Service | **CRITICAL** | UUID filenames, path traversal sanitization | Low |
| `THREAT-T03` | Tampering | Audit Model | **HIGH** | Append-only model `.save()` override | Low |
| `THREAT-T04` | Tampering | Audit QuerySet | **LOW** | `AuditQuerySet` blocks `.update()` and `.delete()` | Low |
| `THREAT-R01` | Repudiation | Document Service | **HIGH** | Historical audit snapshots on deletion | Low |
| `THREAT-R02` | Repudiation | Audit Model | **CRITICAL** | `.delete()` raises ValidationError | Low |
| `THREAT-R03` | Repudiation | Views / Audit Service | **MEDIUM** | `SECURITY_ACCESS_DENIED` persisted on metadata & edit | Low |
| `THREAT-I01` | Information Disclosure | Download Service | **CRITICAL** | Server-side `PermissionService.can_read()` | Low |
| `THREAT-I02` | Information Disclosure | Search Service | **HIGH** | Base queryset pre-filtered to accessible docs | Low |
| `THREAT-I03` | Information Disclosure | Audit Logging | **HIGH** | Recursive metadata & path sanitization | Low |
| `THREAT-D01` | Denial of Service | Upload Validator | **HIGH** | 25 MB size cap before disk write | Low |
| `THREAT-D02` | Denial of Service | Upload Validator | **HIGH** | Binary magic-byte signature inspection | Low |
| `THREAT-D03` | Denial of Service | Storage / Render Disk | **INFORMATIONAL**| Configured persistent volume mount at `/var/data` | Low |
| `THREAT-E01` | Elevation of Privilege | Delete/Share Views | **CRITICAL** | Strict owner-only checks on delete & share | Low |
| `THREAT-E02` | Elevation of Privilege | Admin Dashboard | **CRITICAL** | Separation of admin governance and content | Low |

---

## 4. Verification & Audit Conclusion

All 19 STRIDE threat vectors (including the 4 Sprint 1 remediations) are actively mitigated in the TrustVault codebase and backed by automated regression tests in `core/test_security.py`, `accounts/tests.py`, `documents/tests.py`, `permissions/tests.py`, `audit/tests.py`, and `dashboard/tests.py`. Zero Critical or High unresolved security vulnerabilities exist in the application architecture.
