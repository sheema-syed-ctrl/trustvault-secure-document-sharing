# TrustVault — AI Usage & Prompt Engineering Records

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Candidate:** Senior Engineering Submission
**Policy Compliance:** Full transparency on AI-assisted architectural design, code generation, refactoring, and security verification.

---

## AI Collaboration Overview

TrustVault was engineered with the assistance of advanced Large Language Models (Google Gemini 2.5 Pro / Claude 3.5 Sonnet / Antigravity Agentic Platform) serving as pair architects and security reviewers. In accordance with competition guidelines, all AI interactions were strictly directed by rigorous software architecture specifications, zero-trust constraints, and automated verification loops. Every AI-generated component was subjected to human code review, static analysis (`bandit`, `pip-audit`), and comprehensive test suites before acceptance.

---

## 1. Phase 02: Custom User Model & RBAC Hierarchy

- **Date:** 19 October 2026
- **Phase:** Phase 02 — Authentication & RBAC Engine
- **Model:** Gemini 2.5 Pro (via Antigravity Pair Architect)
- **Primary Objective:** Design a custom Django user model that enforces strict role-based access control (Admin, Document Owner, Viewer) without relying on Django's generic group permissions.

### Prompt Input
```text
Act as a Principal Django Architect and Application Security Engineer.
Project: TrustVault (Snovasys Fresher Hiring Challenge 2026).
Implement Phase 02: Authentication and Role-Based Access Control.
Requirements:
1. Custom User model inheriting AbstractUser in 'accounts'.
2. Role enumeration: ADMIN ('Administrator'), OWNER ('Document Owner'), VIEWER ('Viewer').
3. Disallow public self-registration as ADMIN. Default registration must be VIEWER or OWNER.
4. Only existing ADMINs can elevate or alter user roles via dedicated management interfaces.
5. Prevent self-lockout: ADMINs cannot revoke their own admin status or deactivate themselves.
6. Centralized RBACService enforcing least privilege.
7. Strict session management and CSRF defense.
Provide complete code, migrations, and comprehensive automated test suite.
```

### Architectural Decisions Guided by AI
1. **Model Inheritance:** Selected `AbstractUser` over `AbstractBaseUser` to preserve Django admin compatibility while adding a clean `Role` text choices enumeration (`ADMIN`, `OWNER`, `VIEWER`).
2. **Role Helper Properties:** Implemented `@property` helpers (`is_admin_role`, `is_owner_role`, `is_viewer_role`) directly on the model for clean template and service layer checks.
3. **Dedicated RBAC Service:** Created `accounts.services.RBACService` to decouple authorization logic from views, preventing view-layer logic leaks.

### Human Modifications & Verification
- **Privilege Escalation Gate:** Added explicit validation in `UserRegistrationForm` to strictly prohibit the `role` field from being submitted by anonymous registrants, forcing role assignment to be server-side validated.
- **Admin Self-Protection:** Added service-level validation in `RBACService.update_user_role` that raises `PermissionDenied` if an administrator attempts to remove their own administrative privileges.
- **Automated Verification:** Added 24 automated unit and integration tests in `accounts/tests.py`.

---

## 2. Phase 03 & 05: Private Storage & Protected File Streaming

- **Date:** 19 October 2026
- **Phase:** Phase 03 & Phase 05 — Document Management & File Streaming
- **Model:** Gemini 2.5 Pro
- **Primary Objective:** Implement private file storage completely segregated from public web roots, preventing direct URL access, path traversal, and unauthenticated file downloads.

### Prompt Input
```text
Design the document storage and download authorization engine for TrustVault.
Crucial constraints:
- Documents must NEVER be stored in Django's MEDIA_ROOT or served via web server static handlers.
- Files must be stored in a dedicated PROTECTED_MEDIA_ROOT outside the public root.
- Storage filenames must use cryptographically secure UUIDs (e.g., <uuid>.bin) to eliminate original filename disclosure or file overwrite race conditions.
- Implement strict MIME-type and magic-byte signature validation (disallowing executable extensions .exe, .sh, .py, .bat, etc.).
- Downloads must be streamed via an authenticated controller view (FileResponse) only after server-side PermissionService validation.
- Sanitized Content-Disposition headers with CRLF injection defenses.
```

### Architectural Decisions Guided by AI
1. **Cryptographic Storage Filename:** Stored files as `<uuid4>.bin` on disk while preserving `original_filename` in the database. This eliminates directory traversal, filesystem race conditions, and file extension execution vulnerabilities.
2. **Magic-Byte Signature Verification:** Integrated `filetype` library alongside MIME inspection to detect spoofed file headers (e.g., an executable renamed to `.pdf`).
3. **Streaming Chunking:** Used Django's `FileResponse` with binary file handles rather than loading complete file contents into memory, supporting large enterprise files safely.

### Human Modifications & Verification
- **Path Traversal Escape Check:** Implemented `DocumentService.get_protected_storage_path` using `Path.is_relative_to(root)` to guarantee that resolved file paths never escape `PROTECTED_MEDIA_ROOT` via `..` or symbolic links.
- **Content-Disposition Sanitization:** Sanitized download filenames using RFC 5987 / 6266 escaping, stripping ASCII control characters (`\r`, `\n`) to prevent HTTP response splitting.
- **Post-Commit Physical Deletion:** Wrapped file unlinking in `transaction.on_commit()` to ensure disk cleanup occurs only after database transactions commit.

---

## 3. Phase 04 & 06: Zero-Trust Permission Engine & Access Revocation

- **Date:** 19 October 2026
- **Phase:** Phase 04 & Phase 06 — Permission Engine & Access Revocation
- **Model:** Gemini 2.5 Pro
- **Primary Objective:** Build a default-deny, server-side object-level authorization engine that governs granular READ and EDIT permissions and enforces immediate access cutoff upon revocation.

### Prompt Input
```text
Implement the TrustVault Permission Engine and Access Revocation lifecycle.
Rules:
1. Zero-Trust Default Deny: All access denied unless explicitly permitted.
2. Ownership Precedence: Document Owners have full read, edit, delete, and permission management capabilities on their own documents.
3. Granular Grants: Owners can grant READ or EDIT access to other users.
4. Privilege Boundaries:
   - EDIT permission includes READ access.
   - READ permission does NOT allow editing.
   - Neither READ nor EDIT permission allows document deletion or permission management.
   - Administrators do NOT automatically inherit document access.
5. Immediate Revocation: Revoking access must immediately cut off detail views, downloads, and edits.
6. Atomic permission mutations with complete audit logging.
```

### Architectural Decisions Guided by AI
1. **Model Normalization:** Created `DocumentPermission` with unique constraint `unique_together = ('document', 'user')` and `permission_type` (`READ`, `EDIT`).
2. **Centralized Authority:** Routed all permission evaluations through `PermissionService.can_read()`, `can_edit()`, and `can_manage_permissions()`, eliminating scattered permission checks.
3. **Immediate Cutoff:** Because permissions are queried dynamically from the database on every HTTP request without cached session bypasses, revocation is immediately effective on the next millisecond.

### Human Modifications & Verification
- **Cross-Document IDOR Protection:** Added explicit check in `PermissionService.update_permission` and `revoke_permission_by_id` verifying that the target permission's `document_id` strictly matches the URL's `document_id`.
- **Admin Inaccessibility:** Explicitly coded `PermissionService` to return `False` for administrators attempting to access private document content unless the administrator is the document owner or an explicit grantee.

---

## 4. Phase 07: Persistent Append-Only Audit Trail

- **Date:** 19 October 2026
- **Phase:** Phase 07 — Persistent Audit Trail & Monitoring Engine
- **Model:** Gemini 2.5 Pro
- **Primary Objective:** Architect an append-only, tamper-resistant audit trail that records every security-sensitive action, redacts credentials, and preserves historical metadata even if documents or users are deleted.

### Prompt Input
```text
Build a persistent, database-backed audit logging engine for TrustVault.
Requirements:
1. Log all security events: Auth (login/logout/failed), Document (upload/update/delete/download), Permissions (grant/update/revoke), Security Violations (access denied, unauthorized attempts).
2. Append-Only Model: Override save() and delete() on AuditEvent model to block modification and deletion at the ORM layer.
3. Historical Snapshots: If a Document or User is deleted, preserve historical snapshot fields (document_id, document_name, target_username) so the audit trail remains complete.
4. Deep Metadata Sanitization: Strip passwords, tokens, API keys, session IDs, and absolute server file paths from JSON metadata.
5. Read-only Admin Governance: Provide an audit trail viewer restricted strictly to Administrators and Document Owners (scoped to their own documents).
```

### Architectural Decisions Guided by AI
1. **ORM-Level Immutability:** Overrode `AuditEvent.save()` (preventing updates when `pk` exists) and `AuditEvent.delete()` (raising `PermissionDenied`), preventing accidental or malicious audit truncation.
2. **Snapshot Architecture:** Added `target_document_id_snapshot`, `target_document_name_snapshot`, and `target_username` to survive cascade deletions (`models.SET_NULL`).
3. **Recursive Metadata Sanitizer:** Built `AuditService.sanitize_metadata()` scanning dictionaries and lists recursively for sensitive keys (`password`, `token`, `secret`, `file_path`, etc.).

### Human Modifications & Verification
- **Absolute Path Sanitization:** Added sanitization logic that strips Windows drive paths (`C:\`, `F:\`) and Unix paths (`/tmp/`, `/var/`) from audit metadata to prevent internal server infrastructure reconnaissance.
- **Audit Failure Logging:** Added try/except logging in controllers so audit persistence errors are logged to security loggers without suppressing security alarms.

---

## 5. Phase 08 & 09: Scoped Search Engine & Role-Specific Dashboards

- **Date:** 19 October 2026
- **Phase:** Phase 08 & Phase 09 — Document Discovery & Dashboards
- **Model:** Gemini 2.5 Pro
- **Primary Objective:** Deliver high-performance document discovery and role-tailored dashboards that strictly respect zero-trust isolation.

### Prompt Input
```text
Implement Phase 08 & 09: Scoped Search, Filtering, and Role-Specific Dashboards.
Constraints:
- Search queries must only return documents the requesting user is authorized to access (owned or explicitly shared).
- Search must never disclose unauthorized document titles, categories, or owners.
- Dashboards must provide tailored views:
  * Admin: System metrics, user management, global audit log summary (WITHOUT direct document download access).
  * Document Owner: Storage statistics, owned documents, active shares, document activity feed.
  * Viewer: Shared documents partitioned by READ vs EDIT permission, recent downloads.
- Clean responsive UI using Tailwind CSS utility patterns.
```

### Architectural Decisions Guided by AI
1. **Queryset Scoping:** Encapsulated document visibility queries in `DocumentService.get_accessible_documents(user)`, combining owned and shared documents with `distinct()`.
2. **Privilege-Separated Dashboards:** Implemented distinct view methods (`admin_dashboard`, `owner_dashboard`, `viewer_dashboard`) dispatched by a single router (`dashboard:index`), guaranteeing role segregation.
3. **Administrative Privacy Protection:** Explicitly suppressed document download links and document content views from the Administrator dashboard, respecting the principle that administrators manage infrastructure, not private content.

### Human Modifications & Verification
- **Search Metadata Isolation:** Confirmed via automated tests that searching for a term present only in an unshared document returns 0 results for a non-authorized user.
- **SQL Injection Prevention:** Used Django ORM `icontains` parameters exclusively, preventing raw SQL string interpolation.

---

## 6. Phase 10: STRIDE Threat Modeling & Security Hardening

- **Date:** 19 October 2026
- **Phase:** Phase 10 — Security Testing & STRIDE Threat Model
- **Model:** Gemini 2.5 Pro (via Antigravity Security Suite)
- **Primary Objective:** Perform comprehensive threat analysis across all six STRIDE categories, verify automated defenses, and produce verifiable security test suites.

### Prompt Input
```text
Conduct a comprehensive STRIDE threat modeling analysis for TrustVault.
1. Evaluate all 6 STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
2. Identify 15 concrete threat vectors, defining Preconditions, Impact, Likelihood, Severity, Existing Mitigations, and Verification Tests.
3. Build a dedicated automated security test suite (core/test_security.py) verifying all 18 security domains and 48 controls from the challenge requirements.
4. Ensure zero unresolved Critical or High risks.
```

### Architectural Decisions Guided by AI
1. **STRIDE Threat Matrix:** Documented 15 comprehensive threat scenarios in `THREATS.md`, linking every mitigation directly to production source files and test method names.
2. **Automated Security Regression Suite:** Built 36 automated security tests in `core/test_security.py` executing across 7 test classes in ~2.0 seconds.
3. **Bandit & Pip-Audit Pipeline:** Integrated automated static analysis and vulnerability auditing into the project build verification cycle.

---

## 7. Public Release Cleanup & Hardening Session (19 October 2026)

### Purpose & Objective
Eliminate hardcoded demo credentials across source code and documentation, introduce dynamic cryptographic credential provisioning, implement a production safety gate, and audit the repository for public release readiness.

### Prompt Excerpt Provided to AI
```text
TRUSTVAULT — PUBLIC RELEASE CLEANUP & FINAL TESTING
Remove unsafe hardcoded demo credentials, preserve all mandatory challenge deliverables,
and perform a complete final verification.
- Modify seed_demo_data to eliminate hardcoded passwords, generate cryptographically
  secure random passwords using secrets, allow operator env overrides, display only in terminal.
- Never log passwords or store them in audit metadata.
- Prevent demo creation in production (DEBUG=False) unless ALLOW_DEMO_SEEDING=True.
- Ensure --clean cannot delete non-demo accounts or files.
- Perform public repository secret audit and rebuild clean submission zip.
```

### Architectural Decisions Guided by AI
1. **Cryptographic Credential Provisioning:** Integrated Python's `secrets` module to dynamically generate 16-character high-entropy passwords satisfying all Django `AUTH_PASSWORD_VALIDATORS` criteria, eliminating predictable credentials.
2. **Environment Override Pattern:** Enabled operator overrides (`DEMO_ADMIN_PASSWORD`, `DEMO_OWNER_PASSWORD`, `DEMO_VIEWER_PASSWORD`) for automated testing and programmatic evaluation pipelines.
3. **Production Safety Gate:** Hardened `seed_demo_data` to raise `CommandError` when running under `DEBUG=False` unless explicitly overridden via `ALLOW_DEMO_SEEDING=True`.
4. **Scoped Cleanup Isolation:** Constrained `--clean` to exclusively query and delete accounts and documents matching `admin_demo`, `owner_demo`, and `viewer_demo`.
5. **Zero Credential Leakage:** Kept generated passwords in memory and rendered them solely to the operator's terminal via `self.stdout`, with zero logging or audit trail persistence.

---

## 8. Sprint 1: Claude Adversarial Security Assessment & Remediation (21 October 2026)

### Purpose & Objective
Independently investigate, reproduce, remediate, test, and verify four security and deployment findings identified during an adversarial penetration test:
1. **TV-SEC-001 (Medium):** Missing persistent SECURITY_ACCESS_DENIED audit logging on 403 authorization failures across document metadata inspection, edit, delete, and permission endpoints.
2. **TV-SEC-002 (Low):** Absence of application-level login rate limiting / account lockout against automated credential stuffing and brute force.
3. **TV-SEC-003 (Low):** Django ORM bulk methods (QuerySet.update(), QuerySet.bulk_update(), QuerySet.delete()) bypassing instance-level AuditEvent immutability.
4. **TV-SEC-004 (Informational):** Ephemeral filesystem data loss on containerized PaaS hosting (Render) & path resolution for persistent disks.

### Prompt Excerpt Provided to AI
`	ext
TRUSTVAULT — MASTER SECURITY REMEDIATION & VERIFICATION PROMPT
Sprint 1: Four Vulnerabilities | Independent Validation | Secure Fixes | Regression Testing

You are operating as the Senior Application Security Engineer, Django Backend Architect, DevSecOps Engineer, and Quality Assurance Lead for TrustVault.
Your task is to independently investigate, reproduce, remediate, test, and document all four findings from the first Claude adversarial security assessment.

Project: TrustVault — Secure Document Sharing with a Real Audit Trail
Project directory: F:\Sheema
Assessment report: TRUSTVAULT_ADVERSARIAL_SECURITY_ASSESSMENT.md
Primary objective: Close all four confirmed security and deployment findings without weakening any existing security control.

NON-NEGOTIABLE ENGINEERING RULES:
1. Inspect the existing implementation before changing anything.
2. Never assume a reported vulnerability is genuine without independently validating it.
3. Preserve the existing architecture: Django 5.2, PostgreSQL, clean separation of concerns.
4. Do NOT introduce Supabase or any third-party auth service.
5. Do NOT weaken existing authorization checks.
6. Do NOT rewrite git history.
7. Do NOT push commits or change GitHub repository visibility.
8. Add automated regression tests for every confirmed issue.
9. Verify all existing tests continue to pass.
`

### Architectural Decisions Guided by AI
1. **Defensive Audit Exception Handling (TV-SEC-001):** Integrated AuditService.log_access_denied() directly within documents/views.py and permissions/views.py inside isolated 	ry ... except ... blocks immediately preceding PermissionDenied raises. Ensured that even if an audit log write encounters a database exception, the application logs a warning and still unconditionally denies the user access with HTTP 403 Forbidden.
2. **Multi-Factor Cache-Backed Rate Limiting (TV-SEC-002):** Implemented LoginRateLimitService in ccounts/services.py using Django's built-in django.core.cache abstraction (0 new third-party dependencies). Employs multi-factor tracking (
l:login:<sha256(ip+username)>) with a threshold of 5 failed attempts within 300 seconds (5-minute sliding window). Employs uniform timing and error messaging to eliminate username enumeration, and resets counters upon valid authentication.
3. **ORM-Level Immutability Hardening (TV-SEC-003):** Recognized that overriding model instance save() and delete() methods fails to intercept direct SQL bulk queries generated by Django's QuerySet.update(), QuerySet.bulk_update(), and QuerySet.delete(). Subclassed models.QuerySet into AuditQuerySet and bound it to AuditManager.from_queryset(AuditQuerySet). These bulk methods unconditionally raise ValidationError, enforcing strict immutability at the query interface while safely preserving bulk insertions via ulk_create.
4. **Resilient Persistent Storage Configuration (TV-SEC-004):** Upgraded 	rustvault/settings.py PROTECTED_MEDIA_ROOT using os.path.isabs() to support absolute mount points (/var/data/trustvault_storage), configured
ender.yaml with persistent disk: declarations, and documented cloud persistence tradeoffs and operational requirements.
5. **Bandit Compliance Refactoring:** Replaced silent 	ry ... except ... pass constructs with structured error logging (logger.warning), ensuring Bandit scans pass with zero suppressions or warnings across the entire codebase.

### Human Modifications & Verification
- **Test-Driven Red-Green Cycle:** Added 10 targeted automated regression tests across udit/tests.py (Tests 33–39) and ccounts/tests.py (3 tests for rate limiting, enumeration defense, and lockout reset).
- **Comprehensive Audit Log Assertions:** Tested both successful writes and database exception resilience to ensure security boundaries remain uncompromised under fault conditions.
- **Full Verification Suite:** 287/287 tests passed (0 failures, 0 errors, 0 skips), 0 Django check issues, 0 pending migrations, 0 Bandit issues, and 0 pip-audit vulnerabilities.

---

## AI Collaboration Summary Statistics

| Metric | Measurement |
| :--- | :--- |
| **Total Engineering Phases Covered** | 12 Phases + Public Release Hardening + Security Sprint 1 |
| **Documented AI Interaction Records** | 8 Major Engineering Sessions |
| **Automated Tests Generated/Verified** | 287 Tests (100% Passing) |
| **Static Analysis Findings Resolved** | 0 High, 0 Medium, 0 Low Issues |
| **Dependency Vulnerabilities Found** | 0 Known Vulnerabilities (pip-audit) |
| **Security Controls Implemented** | 52 Controls across 18 Domains |
