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

### 6. Document Permission Engine & Centralized Authorization (Phase 04)
- **Granular Object-Level Access Model:** Implemented `DocumentPermission` in `permissions/models.py`.
  - Links a target `Document` to a registered `User` with explicit `permission_type` (`READ` or `EDIT`).
  - Database-level `UniqueConstraint(fields=['document', 'user'])` prevents duplicate permission assignments.
  - Owners cannot have redundant permission records; document ownership inherently supersedes assigned grants.
- **Permission Precedence & Semantics:**
  1. *Ownership Authority:* Document Owner retains full rights (`can_read`, `can_edit`, `can_delete`, `can_manage_permissions`).
  2. *EDIT Hierarchy:* `EDIT` permission strictly includes `READ` capabilities.
  3. *READ Boundary:* `READ` permission grants read-only access to document metadata and detail view. It does not allow edit or delete.
  4. *Deletion & Permission Management Isolation:* Only the Document Owner can delete a document or manage permissions. Neither `EDIT` nor `READ` grantees have deletion or management authority.
  5. *Strict Administrator Trust Boundary:* Administrators do **not** inherit document access by virtue of their role. An administrator can access a document only if they are the document owner or have an explicit `DocumentPermission`.
  6. *Default-Deny Policy:* Any user without an active, explicit permission or ownership grant is denied (HTTP 403). Anonymous access is strictly prohibited.
- **Centralized Evaluation:** All document views route authorization through `permissions.services.PermissionService` (`can_read`, `can_edit`, `can_delete`, `can_manage_permissions`, `get_accessible_documents`). Client-side UI controls never serve as security boundaries.

### 7. Security Hardening & Administrative Boundary Review (Phase 04 Audit)
- **Django Admin Escalation Protection:**
  - `DocumentPermissionAdmin` and `DocumentAdmin` explicitly disable write permissions (`has_add_permission=False`, `has_change_permission=False`, `has_delete_permission=False`) and designate all model fields as read-only.
  - Closes administrative backdoors where staff or superusers could use Django Admin to grant themselves access, alter user permissions, or reassign document owners.
- **Model Grantor Integrity Validation:**
  - `DocumentPermission.clean()` enforces that if `granted_by` is specified, it must strictly match `document.owner`.
  - Blocks any non-owner or administrator from creating permissions at the ORM layer without owner authorization.
- **Dual-State Deletion Consistency:**
  - `DocumentService.delete_document()` guarantees database atomicity and triggers physical file removal only after successful transaction commit via `transaction.on_commit()`.
  - Rollback safety: If database deletion fails or rolls back, the physical file on disk is preserved, preventing irreversible data loss.
  - Failure logging: Post-commit physical disk removal failures are captured in structured critical logs for administrative auditing without rolling back committed database state.
- **Orphan File Detection and Administrative Recovery Procedure:**
  - *Trigger Condition:* When `os.remove()` encounters an `OSError` (e.g. filesystem lock or permission error) during post-commit cleanup, a `CRITICAL` log entry is written to `logs/security.log`:
    `CRITICAL: Failed to remove physical file from storage post-commit. Document ID: <id>, Storage File: <uuid.bin>, Path: <path>. Error: <err>`
  - *Administrative Recovery Runbook:*
    1. Filter `logs/security.log` for `CRITICAL: Failed to remove physical file from storage post-commit`.
    2. Extract the recorded `storage_filename`.
    3. Verify via database query: `Document.objects.filter(storage_filename=filename).exists() == False` to confirm the record was committed and deleted.
    4. Manually or via scheduled maintenance job, purge the unreferenced `<uuid.bin>` file from `PROTECTED_MEDIA_ROOT`.
    5. Record the administrative file purge in the maintenance log.

### 8. Secure Document Access, Protected File Streaming & Download Authorization (Phase 05)
- **Zero Public Access Architecture:**
  - Protected document media files are never exposed via public static or media URLs.
  - No `MEDIA_URL` routes to `PROTECTED_MEDIA_ROOT`.
  - All file downloads are brokered through the authenticated endpoint `/documents/<doc_id>/download/`.
- **Centralized Download Authorization:**
  - `DocumentService.get_authorized_file(actor, document_id)` requires authenticated actors.
  - Queries document and validates READ authorization via `PermissionService.can_read(actor, document)`.
  - Strict Authorization Matrix:
    - Document Owner: ALLOW
    - READ grantee: ALLOW
    - EDIT grantee: ALLOW
    - Unassigned user: DENY (HTTP 403 Forbidden)
    - Administrator without explicit permission: DENY (HTTP 403 Forbidden)
    - Anonymous user: DENY (HTTP 302 Redirect to Login)
- **Storage Path Resolution & Path Traversal / Symlink Immunity:**
  - `DocumentService.get_protected_storage_path` validates that `(root / storage_filename).resolve().is_relative_to(root.resolve())`.
  - Rejects directory traversal attempts (`../`) and symlink escapes with `PermissionDenied`.
  - Physical file existence is verified on disk before opening; missing files trigger `Http404` and structured error logs without exposing filesystem directory paths in HTTP responses.
- **Efficient Chunked Streaming & Resource Management:**
  - Files are streamed via Django's `FileResponse` in chunks, avoiding buffering large files in RAM.
  - File handles are automatically closed upon response completion.
- **Defensive HTTP Security Headers:**
  - `Content-Type`: Set to verified MIME type stored in database metadata.
  - `Content-Disposition`: Enforced as `attachment; filename="<sanitized>"`. CRLF characters (`\r`, `\n`) are stripped from original filenames to prevent HTTP response splitting.
  - Active formats (e.g. HTML, SVG) are forced to download rather than execute in the browser context.
  - `X-Content-Type-Options`: `nosniff` prevents MIME-sniffing attacks.
  - `Cache-Control`: `private, no-store, max-age=0, must-revalidate` and `Pragma: no-cache` prevent intermediary and local disk caching of confidential payloads.
  - Supported HTTP Methods: Restricted to `GET` and `HEAD` via `@require_http_methods(["GET", "HEAD"])`. `POST`, `PUT`, `DELETE` return `HTTP 405 Method Not Allowed`.

### 9. Document Sharing & Access Revocation Engine (Phase 06)
- **Owner-Controlled Access Delegation:**
  - Document owners have exclusive authority to grant, modify, and revoke access for their documents via `permissions.services.PermissionService`.
  - Non-owners, Viewers, and Administrators attempting permission mutations receive HTTP 403 `PermissionDenied`.
- **Granular Permission Lifecycle (READ & EDIT):**
  - **Grant Workflow:** `PermissionService.grant_permission(actor, document, target_user, permission_type)` creates or updates grants atomically. Self-sharing and sharing with inactive accounts are strictly rejected.
  - **Update Workflow:** `PermissionService.update_permission(actor, document, permission_id, new_permission_type)` safely upgrades or downgrades access between READ and EDIT. Validates that `permission_id` belongs to `document` to prevent cross-document IDOR attacks.
  - **Revocation Workflow:** `PermissionService.revoke_permission_by_id(actor, document, permission_id)` removes grants. Revoked users immediately lose authorization to view metadata, download files, or edit documents. Revocation does not affect the underlying document or physical storage files.
  - **State-Changing Methods:** All grant, update, and revoke endpoints require HTTP `POST` and enforce CSRF verification. `GET` requests cannot mutate permissions and return `HTTP 405 Method Not Allowed`.
- **Bounded User Lookup Security:**
  - Recipient search endpoint (`/permissions/document/<doc_id>/users/search/`) is strictly restricted to authenticated document owners.
  - Excludes inactive accounts, the document owner, and the searching actor to prevent self-sharing and user enumeration.
  - Queries are capped at 20 results (max 50) and select only safe fields (`id`, `username`, `role`), preventing credential or profile data leakage.
- **Audit Logging Preparation:**
  - All successful grants, permission modifications, revocations, and unauthorized access attempts are recorded via structured security logs capturing actor, recipient, document ID, action, and timestamp.

### 10. Persistent Audit Trail & Activity Monitoring Engine (Phase 07)
- **Persistent Database Model (`AuditEvent`):**
  - Database-backed append-only ledger residing in `audit/models.py`.
  - Captures categorical `event_type` (`DOCUMENT_UPLOADED`, `DOCUMENT_DOWNLOADED`, `DOCUMENT_UPDATED`, `DOCUMENT_DELETED`, `PERMISSION_GRANTED`, `PERMISSION_UPDATED`, `PERMISSION_REVOKED`, `SECURITY_ACCESS_DENIED`).
  - Employs dedicated database indexes on `timestamp`, `event_type`, `actor`, `target_document`, and `target_user`.
- **Historical Snapshot Preservation:**
  - Entity references use `models.SET_NULL` for foreign keys so that records survive entity deletions.
  - Snapshots `actor_username`, `target_document_id_snapshot`, `target_document_name_snapshot`, and `target_username` at the moment of event creation, providing unbroken forensic auditability even after user or document deletion.
- **Append-Only Immutability & Tamper Resistance:**
  - Model-layer defense: `AuditEvent.save()` rejects modifications to existing records with `ValidationError`; `AuditEvent.delete()` strictly rejects deletions with `ValidationError`.
  - Administrative boundary: `AuditEventAdmin` disables all write permissions (`has_add_permission=False`, `has_change_permission=False`, `has_delete_permission=False`) and renders all fields read-only.
  - Public interface defense: Audit endpoints accept HTTP `GET` only; `POST`, `PUT`, `DELETE` are rejected with `HTTP 405 Method Not Allowed`.
- **Transactional Consistency & Safe Failure Policy:**
  - Operations that alter database state (`upload_document`, `update_document_metadata`, `delete_document`, `grant_permission`, `update_permission`, `revoke_permission`) execute the business mutation and audit event write within the same atomic transaction (`with transaction.atomic():`).
  - If a transaction rolls back, no orphan or false-success audit event persists.
  - For streaming file delivery (`document_download_view`), the audit event is persisted before file streaming begins; if audit logging fails, streaming is aborted.
- **Data Hygiene & Privacy Enforcement:**
  - `AuditService.sanitize_metadata()` automatically strips passwords, tokens, session IDs, CSRF tokens, secret keys, cookie values, and system filesystem paths before saving.
  - Audit records never store document binary content, raw bytes, or decryption secrets.
- **Role-Governed Audit Dashboards:**
  - **Global Audit Trail (`/audit/`):** Restricted to Administrators (`RBACService.can_view_audit_logs`). Provides filtering by event type, actor, date range, and text search with pagination. Administrators cannot download private document files through this view.
  - **Document Activity Log (`/audit/document/<doc_id>/`):** Restricted to Document Owners. Owners can monitor access, downloads, and permission history for their specific documents.
  - **Zero Viewer Access:** Viewers attempting to access global or document audit logs receive `HTTP 403 Forbidden`.

### 11. Advanced Document Search, Filtering & Discovery Engine (Phase 08)
- **Mandatory Authorization-First Scoping:**
  - Every search and discovery operation begins by querying `PermissionService.get_accessible_documents(user)`.
  - Scoping is executed at the database level before applying text keywords, category filters, date boundaries, ordering, counts, or pagination serialization.
  - Documents where the user lacks ownership or explicit `READ`/`EDIT` permission are never retrieved from the database, preventing unauthorized discovery and information leaks.
  - Administrators with no explicit document grants or ownership discover 0 private documents, preserving administrative isolation.
- **Privacy-Preserving Dynamic Owner Choices:**
  - Owner filter dropdown choices are dynamically derived strictly from `accessible_documents.values_list('owner__username', flat=True).distinct()`.
  - Unrelated document owners are never exposed in UI options, preventing user enumeration across isolated tenant boundaries.
- **Case-Insensitive Multi-Field Text Search:**
  - Substring search (`icontains`) across `name`, `description`, `original_filename`, and `owner__username`.
  - Automatic category label matching against `DocumentCategory.choices`.
  - Queries are stripped and truncated to a safe upper limit (100 characters) to mitigate abuse.
  - **Zero Binary Content Indexing:** Raw binary file payloads are strictly unindexed and cannot be queried via text search.
- **Timezone-Aware Date Range Filtering:**
  - Accepts `date_from` and `date_to` formatted as `YYYY-MM-DD`.
  - Combines with `datetime.time.min` and `datetime.time.max` using the system timezone (`timezone.get_current_timezone()`).
  - Validates date formats and rejects inverted ranges (`date_from > date_to`) gracefully with `ValidationError` and user-facing notifications without 500 errors.
- **Injection-Safe Sorting Whitelist:**
  - Sort keys are validated against an explicit whitelist: `newest` (`-created_at`), `oldest` (`created_at`), `name_asc` (`Lower('name')`), `name_desc` (`Lower('name').desc()`), and `updated` (`-updated_at`).
  - Unrecognized or manipulated sort keys safely fallback to the default (`-created_at`), preventing SQL injection and unauthorized column enumeration.
- **Performance Database Indexes:**
  - `idx_doc_name` on `name` field accelerates alphabetical sorting and prefix lookups.
  - `idx_doc_created_at_desc` on `-created_at` optimizes default chronological ordering.
- **Bounded Pagination & State Preservation:**
  - Page size is bounded at 10 items per page with out-of-range protection via Django's `Paginator.get_page()`.
  - Active search, category, owner, date, and sort parameters are serialized into `filter_querystring` and preserved across pagination links.
- **Immediate Revocation Consistency:**
  - Because discovery directly evaluates `PermissionService.get_accessible_documents()`, access revocation immediately excludes documents from subsequent searches and result counts without stale cache lag.




