# PHASE 04 INDEPENDENT VERIFICATION REPORT
**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Reviewer:** Principal Software Architect, Application Security Engineer & QA Lead  
**Date:** 19 October 2026  
**Final Decision:** **VERIFIED**

---

## 1. Permission Model Design

The object-level permission architecture was implemented in the `permissions` application via the `DocumentPermission` model (`permissions/models.py`):

```python
class PermissionType(models.TextChoices):
    READ = 'READ', _('Read Only (View Metadata and Details)')
    EDIT = 'EDIT', _('Edit (View and Modify Metadata)')

class DocumentPermission(models.Model):
    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    document = models.ForeignKey('documents.Document', on_delete=models.CASCADE, related_name='permissions')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='document_permissions')
    permission_type = models.CharField(max_length=10, choices=PermissionType.choices)
    granted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['document', 'user'], name='unique_document_user_permission')
        ]
```

### Key Architectural Invariants:
1. **Uniqueness Constraint:** Database-level `UniqueConstraint(fields=['document', 'user'])` prohibits duplicate active permissions for the same user on the same document.
2. **Owner Redundancy Defense:** Model-level validation (`clean()`) actively prohibits creating redundant permission records where `user == document.owner`. Ownership provides inherent authority.
3. **Choice Whitelist:** Server-side choice validation prevents assigning unauthorized or forged permission types.
4. **Relational Integrity:** Cascades on document and user deletion ensure no orphan permission records remain in storage.

---

## 2. Permission Evaluation Rules & Semantics

TrustVault enforces explicit permission precedence under a **default-deny** paradigm:

1. **Document Ownership:** Ownership inherently grants `can_read = True`, `can_edit = True`, `can_delete = True`, and `can_manage_permissions = True`. Ownership supersedes any assigned permission.
2. **EDIT Permission Hierarchy:** An explicit `EDIT` permission grant provides read access (`can_read = True`) and metadata editing authority (`can_edit = True`). It does **not** grant deletion authority (`can_delete = False`) or permission delegation (`can_manage_permissions = False`).
3. **READ Permission Boundary:** An explicit `READ` permission grant provides read-only access to document metadata and details (`can_read = True`). It strictly blocks editing (`can_edit = False`) and deletion (`can_delete = False`).
4. **Deletion Exclusivity:** Document deletion is restricted **exclusively** to the Document Owner.
5. **Strict Administrator Trust Boundary:** Platform Administrators do **not** receive automatic or implicit access to private document contents. An administrator is denied document access unless they are the document owner or have been granted an explicit `DocumentPermission`.
6. **Default-Deny Evaluation:** Any user lacking an explicit permission record or ownership is completely denied (HTTP 403 `PermissionDenied`).
7. **Anonymous Users:** Anonymous requests are rejected immediately prior to object evaluation.

---

## 3. Centralized Service Implementation

The `PermissionService` (`permissions/services.py`) encapsulates all authorization logic:

- `can_read(user, document) -> bool`: Evaluates ownership and `READ`/`EDIT` permission records.
- `can_edit(user, document) -> bool`: Evaluates ownership and `EDIT` permission records.
- `can_delete(user, document) -> bool`: Evaluates document ownership.
- `can_manage_permissions(user, document) -> bool`: Evaluates document ownership.
- `has_permission(user, document, permission_type) -> bool`: Validates against specific permission level.
- `get_effective_permission(user, document) -> str | None`: Computes highest effective permission (`'OWNER'`, `'EDIT'`, `'READ'`, or `None`).
- `get_accessible_documents(user, min_permission='READ') -> QuerySet`: Returns authorized documents via indexed database queries (`Q(owner=user) | Q(permissions__user=user)`).

---

## 4. Document View Integration

Existing document endpoints (`documents/views.py`) and services (`documents/services.py`) were integrated with `PermissionService`:

- **Document List (`/documents/`):** Queryset is populated exclusively via `PermissionService.get_accessible_documents(request.user)`. Owners see their owned documents; Viewers see only documents shared with them.
- **Document Detail (`/documents/<id>/`):** Evaluates `PermissionService.can_read(request.user, document)`. Unauthorized access raises HTTP 403 `PermissionDenied`. Context passes `can_edit`, `can_delete`, and `effective_permission` to drive UI state.
- **Metadata Editing (`/documents/<id>/edit/`):** Evaluates `PermissionService.can_edit(request.user, document)`. READ grantees and unauthorized users receive HTTP 403. Form updates only `name`, `category`, and `description`, preserving binary and owner immutability.
- **Document Deletion (`/documents/<id>/delete/`):** Evaluates `PermissionService.can_delete(request.user, document)`. Non-owners receive HTTP 403. Physical storage file and database record are safely purged.

---

## 5. Security Controls & Defenses

1. **IDOR & BOLA Defenses:** URL tampering (manipulating document IDs or UUIDs) cannot bypass server-side checks. `can_read` and `can_edit` are verified on every request against the authenticated `request.user`.
2. **Horizontal Privilege Escalation:** Viewers and cross-owners cannot read, edit, or delete documents belonging to another user.
3. **Vertical Privilege Escalation:** Administrators cannot view or edit private documents without explicit authorization. Viewers cannot promote their permissions to EDIT or OWNER.
4. **Mass Assignment Defense:** `DocumentMetadataEditForm` only exposes `name`, `category`, and `description`. Submitting injected parameters (`owner`, `permission_type`, `user`) has zero effect on the database record.
5. **No Frontend Reliance:** Hidden buttons or absent UI elements are never treated as security controls; all endpoints actively enforce server-side authorization.

---

## 6. Automated Test Coverage & Results

The automated test suite in `permissions/tests.py` covers all 24 required master scenarios plus queryset integration tests.

### Execution Commands & Actual Verbatim Outputs:

#### A. Permissions App Test Suite
```bash
python manage.py test permissions
```
**Output:**
```text
Creating test database for alias 'default'...
.........................
----------------------------------------------------------------------
Ran 25 tests in 109.164s

OK
Destroying test database for alias 'default'...
Found 25 test(s).
System check identified no issues (0 silenced).
```

#### B. Full Regression Test Suite (Pytest)
```bash
pytest
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.1.1, pluggy-1.7.0
django: version: 5.2.18, settings: trustvault.settings (from ini)
rootdir: F:\Sheema
configfile: pytest.ini
plugins: django-4.14.0
collected 71 items

accounts\tests.py ........................                               [ 33%]
core\tests.py ......                                                     [ 42%]
documents\tests.py ................                                      [ 64%]
permissions\tests.py .........................                           [100%]

======================= 71 passed in 239.88s (0:03:59) ========================
```

### Verified Test Matrix (25 Tests in `permissions/tests.py`):
- `test_owner_can_read_own_document`: Owner can view document details.
- `test_owner_can_edit_own_document`: Owner can modify metadata.
- `test_owner_can_delete_own_document`: Owner can delete document.
- `test_owner_can_manage_permissions`: Owner has permission management authority.
- `test_read_user_can_read_authorized_document`: READ grantee can view details.
- `test_read_user_cannot_edit_document`: READ grantee edit attempt yields HTTP 403.
- `test_read_user_cannot_delete_document`: READ grantee delete attempt yields HTTP 403.
- `test_read_user_cannot_manage_permissions`: READ grantee cannot manage permissions.
- `test_edit_user_can_read_authorized_document`: EDIT grantee can view details (EDIT includes READ).
- `test_edit_user_can_edit_authorized_document_metadata`: EDIT grantee can modify title, category, description.
- `test_edit_user_cannot_delete_document`: EDIT grantee delete attempt yields HTTP 403.
- `test_edit_user_cannot_manage_permissions`: EDIT grantee cannot manage permissions.
- `test_unassigned_user_cannot_read_document`: Unassigned user detail attempt yields HTTP 403.
- `test_unassigned_user_cannot_edit_document`: Unassigned user edit attempt yields HTTP 403.
- `test_unassigned_user_cannot_delete_document`: Unassigned user delete attempt yields HTTP 403.
- `test_admin_cannot_access_private_document_solely_by_role`: Administrator without explicit grant yields HTTP 403.
- `test_admin_can_access_document_only_if_independently_authorized`: Administrator with explicit grant can read.
- `test_anonymous_user_cannot_access_protected_document_endpoints`: Unauthenticated requests redirect to login.
- `test_duplicate_document_user_permission_rejected`: Rejection of duplicate document-user permission pair.
- `test_invalid_permission_type_rejected`: Rejection of invalid permission types.
- `test_permission_assigned_to_one_user_does_not_authorize_another`: User B grant never authorizes User C.
- `test_user_cannot_modify_permission_records_through_document_forms`: Parameter tampering on metadata form is ignored.
- `test_ownership_cannot_be_changed_through_metadata_editing`: Form cannot alter document owner.
- `test_changing_document_uuid_cannot_bypass_authorization`: IDOR defense blocks accessing another user's document.
- `test_get_accessible_documents_query`: Queryset returns only owned and explicitly granted documents.

---

## 7. Database Migration Status
- Migration `permissions/migrations/0001_initial.py` applied successfully.
- `python manage.py makemigrations --check --dry-run` confirms: `No changes detected`.
- `python manage.py migrate --check` confirms: clean state with zero pending migrations.
- Existing user records and document records remain intact.

---

## 8. Git Commit Details
- Pending commits to be recorded upon Phase 04 finalization:
  - `feat(phase-04): implement centralized document permission engine`
  - `docs(phase-04): add permission engine verification report and architecture updates`

---

## 9. Known Limitations & Remaining Security Concerns
1. **Sharing UI Not Yet Implemented:** Creation of `DocumentPermission` records is currently handled programmatically and via admin. The user-facing sharing modal, user selector, and revocation workflows belong to Phase 06.
2. **File Download Delivery:** Secure streaming of binary contents with content-disposition headers belongs to Phase 05.
3. **Audit Trail Recording:** Permission evaluations and access denials are not yet persisted to the database audit trail table; this will be wired in Phase 07.

---

## 10. Phase 04 Acceptance Checklist
- [x] `DocumentPermission` database model implemented with unique constraint.
- [x] Centralized `PermissionService` implemented with default-deny evaluation.
- [x] Ownership rules enforced (read, edit, delete, manage).
- [x] READ permission semantics enforced (view only; edit/delete blocked).
- [x] EDIT permission semantics enforced (read + edit allowed; delete blocked).
- [x] Administrator access strictly bounded (no automatic content bypass).
- [x] Existing document views (`list`, `detail`, `edit`, `delete`) integrated with `PermissionService`.
- [x] Automated security tests (25/25 permissions tests, 71/71 full suite) passing cleanly.
- [x] Zero regressions against Phase 01, Phase 02, and Phase 03.
- [x] Phase boundary respected (no file downloads, no sharing UI, no audit logging yet).

---

## 11. Final Decision

# **VERIFIED**

Phase 04 satisfies all architectural, functional, security, and testing requirements. Work has stopped at the Phase 04 boundary.
Awaiting explicit authorization before starting **PHASE 05 — SECURE DOCUMENT ACCESS & STORAGE**.
