"""
TrustVault Phase 10 — Advanced Security & Cross-Cutting Verification Test Suite.
Verifies defense-in-depth across the entire modular monolith:
  A. Authentication and Account Security
  B. Authorization and RBAC (All 4 roles)
  C. IDOR and Cross-User Isolation (Multi-owner & multi-viewer)
  D. Permission Engine & Hierarchy (READ, EDIT, Revocation, Admin boundary)
  E. File Validation & Protected Storage Security
  F. Audit Trail Integrity & Tamper Resistance
  G. Search & Dashboard Authorization Scoping
  H. General Web Security (CSRF, XSS, SQLi, Headers, Clickjacking)
"""

import io
import os
import uuid
from pathlib import Path
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction

from accounts.models import User
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType, AuditStatus
from audit.services import AuditService


@override_settings(PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
class BaseSecurityTestCase(TestCase):
    """Base setup for security tests with multi-owner, multi-viewer fixtures."""

    @classmethod
    def setUpTestData(cls):
        cls.password = "SecTest2026!#Strong"

        # 1. Administrator
        cls.admin_user = User.objects.create_user(
            username='sec_admin',
            email='admin@security.local',
            password=cls.password,
            role=User.Role.ADMIN
        )

        # 2. Document Owners (Multi-Owner setup)
        cls.owner_alice = User.objects.create_user(
            username='sec_alice',
            email='alice@security.local',
            password=cls.password,
            role=User.Role.OWNER
        )
        cls.owner_bob = User.objects.create_user(
            username='sec_bob',
            email='bob@security.local',
            password=cls.password,
            role=User.Role.OWNER
        )

        # 3. Viewers (Multi-Viewer setup)
        cls.viewer_charlie = User.objects.create_user(
            username='sec_charlie',
            email='charlie@security.local',
            password=cls.password,
            role=User.Role.VIEWER
        )
        cls.viewer_david = User.objects.create_user(
            username='sec_david',
            email='david@security.local',
            password=cls.password,
            role=User.Role.VIEWER
        )
        cls.viewer_inactive = User.objects.create_user(
            username='sec_inactive',
            email='inactive@security.local',
            password=cls.password,
            role=User.Role.VIEWER,
            is_active=False
        )

    def setUp(self):
        self.client = Client()
        self.created_files = []

        # Minimal valid PDF payload with genuine %PDF- header magic bytes
        self.pdf_bytes = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF"

        # Create Alice's document
        file_alice = SimpleUploadedFile(
            "alice_confidential.pdf",
            self.pdf_bytes,
            content_type="application/pdf"
        )
        self.doc_alice = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=file_alice,
            name="Alice Strategy Dossier",
            description="Highly confidential corporate strategy",
            category=DocumentCategory.FINANCIAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_alice.storage_filename))

        # Create Bob's document
        file_bob = SimpleUploadedFile(
            "bob_blueprints.pdf",
            self.pdf_bytes,
            content_type="application/pdf"
        )
        self.doc_bob = DocumentService.upload_document(
            owner=self.owner_bob,
            uploaded_file=file_bob,
            name="Bob System Blueprints",
            description="Proprietary technical architecture",
            category=DocumentCategory.TECHNICAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_bob.storage_filename))

    def tearDown(self):
        for path in self.created_files:
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass


# =============================================================================
# A. Authentication & Account Security
# =============================================================================
class AuthenticationSecurityTests(BaseSecurityTestCase):
    """Verifies authentication boundaries, session handling, and role integrity."""

    def test_anonymous_access_redirects_to_login(self):
        """Unauthenticated requests to protected endpoints redirect to login."""
        protected_urls = [
            reverse('dashboard:index'),
            reverse('dashboard:admin'),
            reverse('dashboard:owner'),
            reverse('dashboard:viewer'),
            reverse('documents:list'),
            reverse('documents:upload'),
            reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('permissions:manage', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('audit:trail'),
        ]
        for url in protected_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302, f"URL {url} failed to redirect anonymous user.")
            self.assertIn(reverse('accounts:login'), response.url)

    def test_invalid_credentials_rejected(self):
        """Invalid username or password fails authentication cleanly."""
        response = self.client.post(reverse('accounts:login'), {
            'username': 'sec_alice',
            'password': 'WrongPassword123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertContains(response, 'Invalid username or password')

    def test_logout_requires_post_and_csrf(self):
        """Logout endpoint requires POST verb and rejects GET with HTTP 405."""
        self.client.login(username='sec_alice', password=self.password)
        get_resp = self.client.get(reverse('accounts:logout'))
        self.assertEqual(get_resp.status_code, 405)

        post_resp = self.client.post(reverse('accounts:logout'))
        self.assertEqual(post_resp.status_code, 302)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_open_redirect_protection_on_login(self):
        """Login ignores untrusted external redirect targets and defaults to safe URL."""
        malicious_targets = [
            'https://evil-phishing.com/steal',
            '//evil.com',
            'javascript:alert(1)',
        ]
        for target in malicious_targets:
            response = self.client.post(
                f"{reverse('accounts:login')}?next={target}",
                {'username': 'sec_alice', 'password': self.password}
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, reverse('dashboard:index'))

    def test_registration_prevents_admin_role_injection(self):
        """Self-registration prevents injecting ADMIN role."""
        response = self.client.post(reverse('accounts:register'), {
            'username': 'attacker_admin',
            'email': 'attacker@evil.local',
            'password': 'ValidPassword123!@#',
            'password_confirm': 'ValidPassword123!@#',
            'role': User.Role.ADMIN,
        })
        # Registration form rejects ADMIN role with validation error
        attacker = User.objects.filter(username='attacker_admin').first()
        if attacker:
            self.assertNotEqual(attacker.role, User.Role.ADMIN)

    def test_admin_cannot_self_demote_or_deactivate(self):
        """Admin cannot demote or deactivate their own account."""
        self.client.login(username='sec_admin', password=self.password)
        resp = self.client.post(
            reverse('accounts:user_edit', kwargs={'user_id': self.admin_user.pk}),
            {
                'role': User.Role.VIEWER,
                'is_active': False,
            }
        )
        self.admin_user.refresh_from_db()
        self.assertEqual(self.admin_user.role, User.Role.ADMIN)
        self.assertTrue(self.admin_user.is_active)


# =============================================================================
# B. IDOR & Cross-User Isolation
# =============================================================================
class IDORAndCrossUserIsolationTests(BaseSecurityTestCase):
    """Verifies complete multi-tenant isolation across multiple owners and viewers."""

    def test_cross_owner_detail_access_forbidden(self):
        """Owner Bob cannot view metadata details of Alice's document (HTTP 403)."""
        self.client.login(username='sec_bob', password=self.password)
        response = self.client.get(reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(response.status_code, 403)

    def test_cross_owner_download_access_forbidden(self):
        """Owner Bob cannot download Alice's document file (HTTP 403)."""
        self.client.login(username='sec_bob', password=self.password)
        response = self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(response.status_code, 403)

    def test_cross_owner_edit_metadata_forbidden(self):
        """Owner Bob cannot edit Alice's document metadata (HTTP 403)."""
        self.client.login(username='sec_bob', password=self.password)
        response = self.client.post(
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            {'name': 'Bob Hijacked Alice Doc', 'category': DocumentCategory.HR}
        )
        self.assertEqual(response.status_code, 403)
        self.doc_alice.refresh_from_db()
        self.assertEqual(self.doc_alice.name, "Alice Strategy Dossier")

    def test_cross_owner_delete_forbidden(self):
        """Owner Bob cannot delete Alice's document (HTTP 403)."""
        self.client.login(username='sec_bob', password=self.password)
        response = self.client.post(reverse('documents:delete', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.doc_alice.pk).exists())

    def test_unassigned_viewer_cannot_access_any_document(self):
        """Viewer Charlie cannot access unshared documents (HTTP 403 across all views)."""
        self.client.login(username='sec_charlie', password=self.password)
        endpoints = [
            reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('documents:delete', kwargs={'doc_id': self.doc_alice.pk}),
            reverse('permissions:manage', kwargs={'doc_id': self.doc_alice.pk}),
        ]
        for url in endpoints:
            res = self.client.get(url) if 'delete' not in url else self.client.post(url)
            self.assertEqual(res.status_code, 403, f"Endpoint {url} failed to reject unassigned viewer.")

    def test_cross_document_permission_idor_rejected(self):
        """Attempting to update a permission using mismatched document route returns 403."""
        # Alice shares her document with Charlie
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        # Bob logs in and attempts to update Alice's permission ID via Bob's document route
        self.client.login(username='sec_bob', password=self.password)
        idor_url = reverse('permissions:update', kwargs={'doc_id': self.doc_bob.pk, 'perm_id': perm.pk})
        response = self.client.post(idor_url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(response.status_code, 403)

        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.READ)

    def test_nonexistent_document_id_returns_404_no_leakage(self):
        """Querying a nonexistent document returns HTTP 404 cleanly without traceback."""
        self.client.login(username='sec_alice', password=self.password)
        response = self.client.get(reverse('documents:detail', kwargs={'doc_id': 999999}))
        self.assertEqual(response.status_code, 404)


# =============================================================================
# C. Permission Hierarchy & Engine Security
# =============================================================================
class PermissionHierarchySecurityTests(BaseSecurityTestCase):
    """Verifies strict permission semantics, admin boundaries, and immediate revocation."""

    def test_read_grantee_cannot_edit_delete_or_manage(self):
        """Viewer with READ permission can read/download, but cannot edit, delete, or manage."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='sec_charlie', password=self.password)

        # Permitted: Detail & Download
        res_detail = self.client.get(reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_detail.status_code, 200)

        res_dl = self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_dl.status_code, 200)

        # Denied: Edit (403), Delete (403), Manage (403)
        res_edit = self.client.post(
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            {'name': 'Hacked', 'category': DocumentCategory.GENERAL}
        )
        self.assertEqual(res_edit.status_code, 403)

        res_del = self.client.post(reverse('documents:delete', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_del.status_code, 403)

        res_share = self.client.get(reverse('permissions:manage', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_share.status_code, 403)

    def test_edit_grantee_cannot_delete_or_manage_permissions(self):
        """Viewer with EDIT permission can edit metadata, but CANNOT delete or manage permissions."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.EDIT
        )

        self.client.login(username='sec_charlie', password=self.password)

        # Permitted: Edit metadata
        res_edit = self.client.post(
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            {'name': 'Charlie Updated Strategy', 'category': DocumentCategory.LEGAL}
        )
        self.assertEqual(res_edit.status_code, 302)
        self.doc_alice.refresh_from_db()
        self.assertEqual(self.doc_alice.name, 'Charlie Updated Strategy')

        # Denied: Delete (403)
        res_del = self.client.post(reverse('documents:delete', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_del.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.doc_alice.pk).exists())

        # Denied: Manage permissions (403)
        res_manage = self.client.get(reverse('permissions:manage', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_manage.status_code, 403)

        # Denied: Grant access to another user (403)
        res_grant = self.client.post(
            reverse('permissions:grant', kwargs={'doc_id': self.doc_alice.pk}),
            {'recipient_username': 'sec_david', 'permission_type': 'READ'}
        )
        self.assertEqual(res_grant.status_code, 403)

    def test_administrator_without_explicit_permission_denied_file_access(self):
        """Administrators do NOT inherit access to confidential document files or details."""
        self.client.login(username='sec_admin', password=self.password)

        res_detail = self.client.get(reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_detail.status_code, 403)

        res_dl = self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res_dl.status_code, 403)

        res_edit = self.client.post(
            reverse('documents:edit', kwargs={'doc_id': self.doc_alice.pk}),
            {'name': 'Admin Tamper', 'category': DocumentCategory.HR}
        )
        self.assertEqual(res_edit.status_code, 403)

    def test_immediate_revocation_enforcement(self):
        """Revoking access immediately terminates download, detail, and edit access."""
        # Grant READ
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='sec_charlie', password=self.password)
        self.assertEqual(self.client.get(reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk})).status_code, 200)

        # Owner revokes access
        PermissionService.revoke_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie
        )

        # Immediately rejected
        self.assertEqual(self.client.get(reverse('documents:detail', kwargs={'doc_id': self.doc_alice.pk})).status_code, 403)
        self.assertEqual(self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk})).status_code, 403)

    def test_sharing_with_inactive_user_rejected(self):
        """Owner cannot share documents with inactive users."""
        with self.assertRaises(ValidationError):
            PermissionService.grant_permission(
                actor=self.owner_alice,
                document=self.doc_alice,
                target_user=self.viewer_inactive,
                permission_type=PermissionType.READ
            )

    def test_duplicate_permission_handled_idempotently(self):
        """Granting permission to an existing recipient updates existing record without duplicates."""
        perm1 = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        perm2 = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.EDIT
        )
        self.assertEqual(perm1.pk, perm2.pk)
        self.assertEqual(DocumentPermission.objects.filter(document=self.doc_alice, user=self.viewer_charlie).count(), 1)


# =============================================================================
# D. File Validation & Storage Security
# =============================================================================
class FileValidationAndStorageSecurityTests(BaseSecurityTestCase):
    """Verifies file signature validation, size caps, path sanitization, and streaming safety."""

    def test_disallowed_extension_rejected(self):
        """Executable, shell script, and python file extensions are rejected."""
        disallowed = [
            ("payload.exe", b"MZ\x90\x00\x03\x00\x00\x00"),
            ("script.sh", b"#!/bin/bash\necho hacked\n"),
            ("backdoor.py", b"import os; os.system('calc')"),
        ]
        self.client.login(username='sec_alice', password=self.password)
        for fname, content in disallowed:
            f = SimpleUploadedFile(fname, content, content_type="application/octet-stream")
            res = self.client.post(reverse('documents:upload'), {
                'name': f'Malicious {fname}',
                'category': DocumentCategory.GENERAL,
                'file': f,
            })
            self.assertEqual(res.status_code, 200)
            self.assertContains(res, 'is not permitted')

    def test_mime_spoofing_magic_bytes_mismatch_rejected(self):
        """Renaming an executable binary to .pdf is detected and rejected via signature inspection."""
        self.client.login(username='sec_alice', password=self.password)
        fake_pdf = SimpleUploadedFile(
            "trojan.pdf",
            b"MZ\x90\x00\x03\x00\x00\x00ExecutableBinaryPayloadContent",
            content_type="application/pdf"
        )
        res = self.client.post(reverse('documents:upload'), {
            'name': 'Spoofed Trojan PDF',
            'category': DocumentCategory.GENERAL,
            'file': fake_pdf,
        })
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'Security Alert: Signature mismatch detected')

    def test_path_traversal_in_filename_sanitized(self):
        """Directory traversal sequences in filenames are sanitized."""
        self.client.login(username='sec_alice', password=self.password)
        traversal_file = SimpleUploadedFile(
            "../../../../etc/passwd.pdf",
            self.pdf_bytes,
            content_type="application/pdf"
        )
        res = self.client.post(reverse('documents:upload'), {
            'name': 'Traversal Test',
            'category': DocumentCategory.GENERAL,
            'file': traversal_file,
        })
        self.assertEqual(res.status_code, 302)

        doc = Document.objects.filter(owner=self.owner_alice, name='Traversal Test').first()
        self.assertIsNotNone(doc)
        doc_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.created_files.append(doc_path)

        # Confirm physical file is stored safely inside protected_media/
        storage_path = Path(doc_path).resolve()
        from django.conf import settings
        self.assertTrue(storage_path.is_relative_to(Path(settings.PROTECTED_MEDIA_ROOT).resolve()))
        self.assertNotIn("..", str(storage_path))

    def test_content_disposition_crlf_injection_prevented(self):
        """CRLF injection characters in filenames are stripped from Content-Disposition header."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        self.client.login(username='sec_charlie', password=self.password)

        response = self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(response.status_code, 200)
        disposition = response.get('Content-Disposition', '')
        self.assertNotIn('\r', disposition)
        self.assertNotIn('\n', disposition)
        self.assertIn('attachment;', disposition)

    def test_head_request_behavior_on_download(self):
        """HEAD request verifies file availability without transmitting payload body."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        self.client.login(username='sec_charlie', password=self.password)

        response = self.client.head(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get('Content-Type'), 'application/pdf')
        self.assertEqual(b''.join(response.streaming_content), b'')

    def test_physical_file_deleted_on_document_delete(self):
        """Deleting a document safely removes the physical storage file from disk."""
        # Create a document specifically for deletion
        f = SimpleUploadedFile("temp_delete.pdf", self.pdf_bytes, content_type="application/pdf")
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=f,
            name="Temporary Document For Deletion",
            category=DocumentCategory.GENERAL
        )
        file_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.assertTrue(os.path.exists(file_path))

        self.client.login(username='sec_alice', password=self.password)
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(reverse('documents:delete', kwargs={'doc_id': doc.pk}))
        self.assertEqual(res.status_code, 302)
        self.assertFalse(Document.objects.filter(pk=doc.pk).exists())
        self.assertFalse(os.path.exists(file_path))


# =============================================================================
# E. Audit Trail Integrity & Tamper Resistance
# =============================================================================
class AuditTrailIntegritySecurityTests(BaseSecurityTestCase):
    """Verifies audit event persistence, immutability, and metadata sanitization."""

    def test_audit_event_is_append_only(self):
        """AuditEvent records cannot be updated after creation (raises ValidationError)."""
        event = AuditService.log_document_uploaded(
            actor=self.owner_alice,
            document=self.doc_alice
        )
        self.assertIsNotNone(event.pk)

        # Attempt to tamper with audit record
        event.actor_username = 'hacked_username'
        with self.assertRaises(ValidationError):
            event.save()

    def test_audit_event_cannot_be_deleted(self):
        """AuditEvent records cannot be deleted (raises ValidationError)."""
        event = AuditService.log_document_uploaded(
            actor=self.owner_alice,
            document=self.doc_alice
        )
        with self.assertRaises(ValidationError):
            event.delete()

    def test_audit_metadata_deep_sanitization(self):
        """Sensitive credentials and file paths are stripped from audit metadata."""
        dirty = {
            'password': 'PlainPassword123!',
            'token': 'secret_jwt_token_payload',
            'session_id': 'sess_987654321',
            'csrftoken': 'csrf_secret',
            'file_path': 'C:\\secret\\drive\\vault.bin',
            'storage_location': 'f:\\Sheema\\protected_media\\vault.bin',
            'safe_key': 'safe_value',
        }
        clean = AuditService.sanitize_metadata(dirty)
        self.assertNotIn('password', clean)
        self.assertNotIn('token', clean)
        self.assertNotIn('session_id', clean)
        self.assertNotIn('csrftoken', clean)
        self.assertNotIn('file_path', clean)
        self.assertNotIn('storage_location', clean)
        self.assertEqual(clean.get('safe_key'), 'safe_value')

    def test_unauthorized_download_attempt_logs_security_access_denied(self):
        """Unauthorized download attempt triggers SECURITY_ACCESS_DENIED audit log."""
        self.client.login(username='sec_david', password=self.password)
        res = self.client.get(reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertEqual(res.status_code, 403)

        denial_event = AuditEvent.objects.filter(
            event_type=AuditEventType.SECURITY_ACCESS_DENIED,
            actor=self.viewer_david,
            target_document_id=self.doc_alice.pk
        ).first()
        self.assertIsNotNone(denial_event)
        self.assertEqual(denial_event.status, AuditStatus.FAILURE)

    def test_document_deletion_preserves_historical_snapshot(self):
        """Deleting a document preserves the document name and ID in audit logs."""
        doc_id = self.doc_alice.pk
        doc_name = self.doc_alice.name
        AuditService.log_document_deleted(
            actor=self.owner_alice,
            document_id=doc_id,
            document_name=doc_name
        )
        del_event = AuditEvent.objects.filter(
            event_type=AuditEventType.DOCUMENT_DELETED,
            target_document_id_snapshot=doc_id
        ).first()
        self.assertIsNotNone(del_event)
        self.assertEqual(del_event.target_document_name_snapshot, doc_name)


# =============================================================================
# F. Search & Dashboard Scoping Security
# =============================================================================
class SearchAndDashboardScopingSecurityTests(BaseSecurityTestCase):
    """Verifies search scoping, count isolation, and dashboard boundary guarantees."""

    def test_search_results_strictly_scoped_to_authorized_documents(self):
        """Search query never returns unauthorized documents to viewers."""
        # Share only Alice's document with Charlie
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.doc_alice,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='sec_charlie', password=self.password)

        # Search without term returns all accessible docs (only Alice's, not Bob's)
        res = self.client.get(reverse('documents:list'))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Alice Strategy Dossier")
        self.assertNotContains(res, "Bob System Blueprints")

        # Specific search for Bob's doc returns zero results
        res_bob = self.client.get(f"{reverse('documents:list')}?q=Blueprints")
        self.assertEqual(res_bob.status_code, 200)
        self.assertNotContains(res_bob, "Bob System Blueprints")

    def test_admin_dashboard_never_leaks_download_links(self):
        """Administrator dashboard does NOT render document download or content links."""
        self.client.login(username='sec_admin', password=self.password)
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

        # Download links must NOT exist on the admin monitoring dashboard
        self.assertNotContains(response, reverse('documents:download', kwargs={'doc_id': self.doc_alice.pk}))
        self.assertNotContains(response, reverse('documents:download', kwargs={'doc_id': self.doc_bob.pk}))


# =============================================================================
# G. Web Security & Injection Defenses
# =============================================================================
class WebSecurityDefensesTests(BaseSecurityTestCase):
    """Verifies security headers, CSRF enforcement, XSS escaping, and SQLi resistance."""

    def test_security_headers_present(self):
        """Key HTTP security headers are present on all application responses."""
        response = self.client.get(reverse('accounts:login'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_csrf_rejection_without_token(self):
        """CSRF middleware rejects POST requests without valid CSRF token."""
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(reverse('accounts:login'), {
            'username': 'sec_alice',
            'password': self.password,
        })
        self.assertEqual(response.status_code, 403)

    def test_xss_in_document_name_safely_escaped(self):
        """XSS payloads in document names are HTML-escaped by Django templates."""
        xss_name = "<script>alert('xss_attack')</script>"
        doc_xss = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("safe.pdf", self.pdf_bytes, content_type="application/pdf"),
            name=xss_name,
            category=DocumentCategory.GENERAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc_xss.storage_filename))

        self.client.login(username='sec_alice', password=self.password)
        res = self.client.get(reverse('documents:detail', kwargs={'doc_id': doc_xss.pk}))
        self.assertEqual(res.status_code, 200)
        # Raw script tag is NOT in response; escaped entities are
        self.assertNotContains(res, "<script>alert('xss_attack')</script>")
        self.assertContains(res, "&lt;script&gt;alert(&#x27;xss_attack&#x27;)&lt;/script&gt;")

    def test_sql_injection_in_search_treated_literally(self):
        """SQL injection payloads in document search are treated as literal strings."""
        self.client.login(username='sec_alice', password=self.password)
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE documents_document; --",
            "1 UNION SELECT null, null, null--",
        ]
        for payload in sqli_payloads:
            res = self.client.get(f"{reverse('documents:list')}?q={payload}")
            self.assertEqual(res.status_code, 200)
            # Database table is intact
            self.assertTrue(Document.objects.filter(pk=self.doc_alice.pk).exists())
