"""
Automated test suite for Phase 03: Document Management Engine.
Tests document upload, binary magic byte verification, cross-owner isolation,
safe storage cleanup, path traversal prevention, and metadata editing.
"""

import os
from pathlib import Path
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import PermissionDenied, ValidationError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import FileResponse
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from documents.validators import validate_file_upload, sanitize_filename
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService

User = get_user_model()


class DocumentManagementTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.password = "StrongPassword123!@#"

        # Create test users
        self.owner_alice = User.objects.create_user(
            username='owner_alice',
            email='alice@vault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.owner_bob = User.objects.create_user(
            username='owner_bob',
            email='bob@vault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_charlie = User.objects.create_user(
            username='viewer_charlie',
            email='charlie@vault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.admin_david = User.objects.create_user(
            username='admin_david',
            email='david@vault.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        # Sample valid binary payloads
        self.valid_pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        self.valid_png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        self.valid_txt_bytes = b"TrustVault confidential board meeting minutes and strategy 2026."

        self.created_files = []

    def tearDown(self):
        # Clean up any created test files in protected_media
        for path in self.created_files:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # 1. Valid Uploads & File Validation
    # -------------------------------------------------------------------------
    def test_valid_pdf_upload(self):
        """Verify successful upload of valid PDF file by Document Owner."""
        self.client.login(username='owner_alice', password=self.password)
        pdf_file = SimpleUploadedFile("report.pdf", self.valid_pdf_bytes, content_type="application/pdf")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Q3 Financial Audit',
            'category': DocumentCategory.FINANCIAL,
            'description': 'Confidential Q3 balance sheet',
            'file': pdf_file,
        })
        self.assertEqual(response.status_code, 302)

        doc = Document.objects.get(name='Q3 Financial Audit')
        self.assertEqual(doc.owner, self.owner_alice)
        self.assertEqual(doc.mime_type, 'application/pdf')
        self.assertEqual(doc.category, DocumentCategory.FINANCIAL)
        self.assertTrue(doc.sha256_hash)

        target_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.created_files.append(target_path)
        self.assertTrue(target_path.exists())

    def test_valid_png_upload(self):
        """Verify upload of valid PNG image."""
        self.client.login(username='owner_alice', password=self.password)
        png_file = SimpleUploadedFile("architecture.png", self.valid_png_bytes, content_type="image/png")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'System Diagram',
            'category': DocumentCategory.TECHNICAL,
            'file': png_file,
        })
        self.assertEqual(response.status_code, 302)
        doc = Document.objects.get(name='System Diagram')
        self.assertEqual(doc.mime_type, 'image/png')
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

    def test_valid_txt_upload(self):
        """Verify upload of valid plain text file."""
        self.client.login(username='owner_alice', password=self.password)
        txt_file = SimpleUploadedFile("notes.txt", self.valid_txt_bytes, content_type="text/plain")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Meeting Notes',
            'category': DocumentCategory.GENERAL,
            'file': txt_file,
        })
        self.assertEqual(response.status_code, 302)
        doc = Document.objects.get(name='Meeting Notes')
        self.assertEqual(doc.mime_type, 'text/plain')
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

    # -------------------------------------------------------------------------
    # 2. File Signature Verification & Attack Defenses
    # -------------------------------------------------------------------------
    def test_disallowed_extension_rejected(self):
        """SECURITY TEST: Executable and script extensions must be rejected."""
        self.client.login(username='owner_alice', password=self.password)
        bad_file = SimpleUploadedFile("payload.exe", b"MZ\x90\x00\x03\x00\x00\x00", content_type="application/octet-stream")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Exploit Script',
            'category': DocumentCategory.GENERAL,
            'file': bad_file,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Document.objects.filter(name='Exploit Script').exists())
        self.assertContains(response, 'is not permitted')

    def test_file_signature_spoofing_rejected(self):
        """
        SECURITY TEST:
        An attacker renames a PNG or executable to .pdf.
        The magic-byte validator must detect signature mismatch and block upload.
        """
        self.client.login(username='owner_alice', password=self.password)
        # Upload PNG bytes with .pdf extension
        spoofed_file = SimpleUploadedFile("fake_document.pdf", self.valid_png_bytes, content_type="application/pdf")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Spoofed PDF',
            'category': DocumentCategory.LEGAL,
            'file': spoofed_file,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Document.objects.filter(name='Spoofed PDF').exists())
        self.assertContains(response, 'Signature mismatch detected')

    @override_settings(MAX_UPLOAD_SIZE_BYTES=100)
    def test_oversized_file_rejected(self):
        """SECURITY TEST: File exceeding size cap must be rejected."""
        self.client.login(username='owner_alice', password=self.password)
        big_payload = b"%PDF-1.4\n" + (b"A" * 500)
        big_file = SimpleUploadedFile("big.pdf", big_payload, content_type="application/pdf")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Oversized PDF',
            'category': DocumentCategory.GENERAL,
            'file': big_file,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Document.objects.filter(name='Oversized PDF').exists())
        self.assertContains(response, 'exceeds maximum limit')

    def test_duplicate_filenames_handled_uniquely(self):
        """
        SECURITY TEST:
        Uploading two documents with identical user filenames must result in
        separate unique storage filenames and distinct database records.
        """
        self.client.login(username='owner_alice', password=self.password)

        file1 = SimpleUploadedFile("report.pdf", self.valid_pdf_bytes, content_type="application/pdf")
        res1 = self.client.post(reverse('documents:upload'), {
            'name': 'Report A',
            'category': DocumentCategory.GENERAL,
            'file': file1
        })
        self.assertEqual(res1.status_code, 302)

        file2 = SimpleUploadedFile("report.pdf", self.valid_pdf_bytes, content_type="application/pdf")
        res2 = self.client.post(reverse('documents:upload'), {
            'name': 'Report B',
            'category': DocumentCategory.GENERAL,
            'file': file2
        })
        self.assertEqual(res2.status_code, 302)

        doc_a = Document.objects.get(name='Report A')
        doc_b = Document.objects.get(name='Report B')

        self.assertNotEqual(doc_a.storage_filename, doc_b.storage_filename)
        self.created_files.append(DocumentService.get_protected_storage_path(doc_a.storage_filename))
        self.created_files.append(DocumentService.get_protected_storage_path(doc_b.storage_filename))

    def test_path_traversal_filename_sanitized(self):
        """SECURITY TEST: Dangerous path traversal in filename must be stripped."""
        raw = "../../../etc/passwd.pdf"
        sanitized = sanitize_filename(raw)
        self.assertEqual(sanitized, "passwd.pdf")
        self.assertNotIn("..", sanitized)
        self.assertNotIn("/", sanitized)

    # -------------------------------------------------------------------------
    # 3. Role-Based Upload & Deletion Access Control
    # -------------------------------------------------------------------------
    def test_viewer_cannot_upload_document(self):
        """SECURITY TEST (RBAC): Viewers cannot upload documents (HTTP 403)."""
        self.client.login(username='viewer_charlie', password=self.password)
        pdf_file = SimpleUploadedFile("report.pdf", self.valid_pdf_bytes, content_type="application/pdf")

        response = self.client.post(reverse('documents:upload'), {
            'name': 'Viewer Illegal Upload',
            'file': pdf_file,
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Document.objects.filter(name='Viewer Illegal Upload').exists())

    def test_viewer_cannot_delete_document(self):
        """SECURITY TEST (RBAC): Viewers cannot delete documents (HTTP 403)."""
        # Alice creates doc
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Secret"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        # Charlie attempts delete
        self.client.login(username='viewer_charlie', password=self.password)
        response = self.client.post(reverse('documents:delete', args=[doc.id]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=doc.id).exists())

    # -------------------------------------------------------------------------
    # 4. Cross-Owner Document Isolation
    # -------------------------------------------------------------------------
    def test_cross_owner_detail_view_forbidden(self):
        """
        SECURITY TEST (IDOR Defense):
        Owner B must NOT be able to view Owner A's private document details (HTTP 403).
        """
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Strategy"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        self.client.login(username='owner_bob', password=self.password)
        response = self.client.get(reverse('documents:detail', args=[doc.id]))
        self.assertEqual(response.status_code, 403)

    def test_cross_owner_edit_forbidden(self):
        """SECURITY TEST: Owner B cannot edit Owner A's document metadata (HTTP 403)."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Strategy"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        self.client.login(username='owner_bob', password=self.password)
        response = self.client.post(reverse('documents:edit', args=[doc.id]), {
            'name': 'Tampered by Bob',
            'category': DocumentCategory.GENERAL,
        })
        self.assertEqual(response.status_code, 403)
        doc.refresh_from_db()
        self.assertEqual(doc.name, "Alice Strategy")

    def test_cross_owner_delete_forbidden(self):
        """SECURITY TEST: Owner B cannot delete Owner A's document (HTTP 403)."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Strategy"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        self.client.login(username='owner_bob', password=self.password)
        response = self.client.post(reverse('documents:delete', args=[doc.id]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=doc.id).exists())

    def test_owner_sees_only_own_documents_in_list(self):
        """Owner A's list view contains only Owner A's documents, never Owner B's."""
        doc_a = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("a.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Document"
        )
        doc_b = DocumentService.upload_document(
            owner=self.owner_bob,
            uploaded_file=SimpleUploadedFile("b.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Bob Document"
        )
        self.created_files.extend([
            DocumentService.get_protected_storage_path(doc_a.storage_filename),
            DocumentService.get_protected_storage_path(doc_b.storage_filename),
        ])

        self.client.login(username='owner_alice', password=self.password)
        response = self.client.get(reverse('documents:list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alice Document")
        self.assertNotContains(response, "Bob Document")

    # -------------------------------------------------------------------------
    # 5. Metadata Editing & Safe Storage Cleanup
    # -------------------------------------------------------------------------
    def test_owner_can_edit_metadata(self):
        """Owner can edit title, category, and description of their document."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("a.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Original Title",
            description="Original description",
            category=DocumentCategory.GENERAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        self.client.login(username='owner_alice', password=self.password)
        response = self.client.post(reverse('documents:edit', args=[doc.id]), {
            'name': 'Updated Title',
            'category': DocumentCategory.FINANCIAL,
            'description': 'Updated description',
        })
        self.assertRedirects(response, reverse('documents:detail', args=[doc.id]))

        doc.refresh_from_db()
        self.assertEqual(doc.name, 'Updated Title')
        self.assertEqual(doc.category, DocumentCategory.FINANCIAL)
        self.assertEqual(doc.description, 'Updated description')

    def test_safe_storage_cleanup_on_delete(self):
        """Deleting a document permanently removes the physical storage file from disk."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("cleanup.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="File to Clean"
        )
        target_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.assertTrue(target_path.exists())

        self.client.login(username='owner_alice', password=self.password)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse('documents:delete', args=[doc.id]))
        self.assertRedirects(response, reverse('documents:list'))

        # DB record removed
        self.assertFalse(Document.objects.filter(pk=doc.id).exists())
        # Disk file removed
        self.assertFalse(target_path.exists())

    def test_deletion_preserves_file_when_transaction_rolls_back(self):
        """Dual-state consistency: If database transaction rolls back, physical file is preserved."""
        from django.db import transaction
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("rollback.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Rollback Test Doc"
        )
        target_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.created_files.append(target_path)
        self.assertTrue(target_path.exists())

        doc_id = doc.id
        # Simulate transaction rollback during delete
        try:
            with transaction.atomic():
                DocumentService.delete_document(doc, self.owner_alice)
                raise RuntimeError("Simulated database failure during deletion transaction")
        except RuntimeError:
            pass

        # Transaction rolled back: DB record must still exist
        self.assertTrue(Document.objects.filter(pk=doc_id).exists())
        # File must NOT have been removed
        self.assertTrue(target_path.exists())

    def test_deletion_handles_missing_file_gracefully(self):
        """If physical storage file is already missing on disk, DB record deletion completes cleanly."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("missing.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Missing File Test Doc"
        )
        target_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        # Pre-delete the file to simulate missing disk file
        if target_path.exists():
            os.remove(target_path)

        with self.captureOnCommitCallbacks(execute=True):
            result = DocumentService.delete_document(doc, self.owner_alice)

        self.assertTrue(result)
        self.assertFalse(Document.objects.filter(pk=doc.id).exists())

    def test_deletion_handles_disk_removal_error_gracefully(self):
        """If os.remove raises OSError during post-commit cleanup, it is caught and logged."""
        from unittest.mock import patch
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("oserror.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="OSError Test Doc"
        )
        target_path = DocumentService.get_protected_storage_path(doc.storage_filename)
        self.created_files.append(target_path)

        with patch('documents.services.os.remove', side_effect=OSError("Access denied simulation")):
            with self.captureOnCommitCallbacks(execute=True):
                result = DocumentService.delete_document(doc, self.owner_alice)

        self.assertTrue(result)
        self.assertFalse(Document.objects.filter(pk=doc.id).exists())


class DocumentDownloadAndDeliveryTests(TestCase):
    """
    Automated security and functional test suite for Phase 05:
    Secure Document Access, Protected File Streaming & Download Authorization.
    Covers:
      - Mandatory authentication.
      - Granular role and permission authorization (Owner, READ, EDIT allowed; Unassigned, Admin, Anonymous denied).
      - Parameter tampering & cross-user isolation.
      - Immediate reflection of permission revocation.
      - Path traversal, arbitrary paths, and symlink escape defenses.
      - Missing storage file resilience and path concealment.
      - Content-Disposition CRLF injection sanitation.
      - Accurate Content-Type and chunked streaming verification.
      - Security headers (nosniff, private no-store cache control).
      - HTTP method constraints (GET/HEAD permitted, POST/PUT/DELETE rejected).
      - Template UI action rendering.
      - Service-layer owner validation for permission grants and revocations.
    """

    def setUp(self):
        self.client = Client()
        self.password = "StrongPassword123!@#"

        self.owner_alice = User.objects.create_user(
            username='download_alice',
            email='alice@download.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.owner_bob = User.objects.create_user(
            username='download_bob',
            email='bob@download.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_charlie = User.objects.create_user(
            username='download_charlie',
            email='charlie@download.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_david = User.objects.create_user(
            username='download_david',
            email='david@download.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.admin_eve = User.objects.create_user(
            username='download_eve',
            email='eve@download.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        self.valid_pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"

        self.alice_doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice_vault.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Alice Confidential Strategy",
            description="Alice's confidential business document.",
            category=DocumentCategory.FINANCIAL
        )

        self.created_files = [
            DocumentService.get_protected_storage_path(self.alice_doc.storage_filename)
        ]

    def tearDown(self):
        for path in self.created_files:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # 1. Download Authorization Matrix
    # -------------------------------------------------------------------------
    def test_owner_can_download_own_document(self):
        """1. Document Owner can download their own document."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(b''.join(res.streaming_content), self.valid_pdf_bytes)

    def test_read_grantee_can_download_document(self):
        """2. READ grantee can download document."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        self.client.login(username='download_charlie', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(b''.join(res.streaming_content), self.valid_pdf_bytes)

    def test_edit_grantee_can_download_document(self):
        """3. EDIT grantee can download document."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_david,
            permission_type=PermissionType.EDIT
        )
        self.client.login(username='download_david', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(b''.join(res.streaming_content), self.valid_pdf_bytes)

    def test_unassigned_user_cannot_download_document(self):
        """4. Unassigned user receives HTTP 403 Forbidden when attempting download."""
        self.client.login(username='download_bob', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)

    def test_admin_without_explicit_permission_cannot_download_document(self):
        """5. Administrator without explicit permission receives HTTP 403 Forbidden."""
        self.client.login(username='download_eve', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)

    def test_anonymous_user_cannot_download_document(self):
        """6. Anonymous user is redirected to login page."""
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.url.startswith(reverse('accounts:login')))

    def test_user_cannot_download_another_users_document_by_changing_id(self):
        """7. Parameter tampering / IDOR defense: Changing document ID fails authorization."""
        bob_doc = DocumentService.upload_document(
            owner=self.owner_bob,
            uploaded_file=SimpleUploadedFile("bob.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="Bob Secret Document"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(bob_doc.storage_filename))

        # Charlie has READ on Alice's doc, but tries to download Bob's doc
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        self.client.login(username='download_charlie', password=self.password)
        res = self.client.get(reverse('documents:download', args=[bob_doc.id]))
        self.assertEqual(res.status_code, 403)

    def test_permission_revocation_reflected_immediately(self):
        """8. Permission changes/revocations take immediate effect."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        self.client.login(username='download_charlie', password=self.password)
        res1 = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res1.status_code, 200)

        # Alice revokes Charlie's permission
        PermissionService.revoke_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie
        )

        # Charlie attempts download again immediately
        res2 = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res2.status_code, 403)

    # -------------------------------------------------------------------------
    # 2. File Security & Storage Path Defenses
    # -------------------------------------------------------------------------
    def test_missing_physical_file_handled_safely(self):
        """9. Missing physical storage file returns 404 without exposing internal paths."""
        target_path = DocumentService.get_protected_storage_path(self.alice_doc.storage_filename)
        if target_path.exists():
            os.remove(target_path)

        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 404)
        # Verify internal filesystem path is NOT leaked in the response content
        self.assertNotIn(str(settings.BASE_DIR).encode(), res.content)
        self.assertNotIn(b"protected_media", res.content)

    def test_nonexistent_document_id_returns_404(self):
        """10. Requesting nonexistent document returns 404."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[999999]))
        self.assertEqual(res.status_code, 404)

    def test_path_traversal_in_storage_path_rejected(self):
        """11. Path traversal attempt in storage filename raises PermissionDenied."""
        with self.assertRaises(PermissionDenied):
            DocumentService.get_protected_storage_path("../../../etc/passwd")

        with self.assertRaises(PermissionDenied):
            DocumentService.get_protected_storage_path("..\\..\\boot.ini")

    def test_symlink_escape_rejected(self):
        """12. Symlink pointing outside PROTECTED_MEDIA_ROOT raises PermissionDenied."""
        root = Path(settings.PROTECTED_MEDIA_ROOT)
        symlink_path = root / "escape_symlink.bin"
        try:
            # Create symlink pointing to parent folder
            os.symlink(settings.BASE_DIR, symlink_path)
            self.created_files.append(symlink_path)
            with self.assertRaises(PermissionDenied):
                DocumentService.get_protected_storage_path("escape_symlink.bin")
        except (OSError, NotImplementedError):
            # On Windows without developer mode/admin rights, symlink creation may require privilege
            pass

    def test_header_injection_in_filename_sanitized(self):
        """13. Carriage returns and newlines in original filename are sanitized from Content-Disposition."""
        doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("report\r\nX-Injected: evil.pdf", self.valid_pdf_bytes, content_type="application/pdf"),
            name="CRLF Injected File"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(doc.storage_filename))

        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[doc.id]))
        self.assertEqual(res.status_code, 200)
        cd_header = res['Content-Disposition']
        self.assertNotIn("\r", cd_header)
        self.assertNotIn("\n", cd_header)
        self.assertNotIn("X-Injected", res.headers)

    # -------------------------------------------------------------------------
    # 3. HTTP Headers, Streaming, & Method Enforcement
    # -------------------------------------------------------------------------
    def test_correct_content_type_header(self):
        """14. Download response sets verified MIME Content-Type."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res['Content-Type'], 'application/pdf')

    def test_safe_content_disposition_attachment(self):
        """15. Download response sets attachment disposition."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertIn('attachment;', res['Content-Disposition'])
        self.assertIn('alice_vault.pdf', res['Content-Disposition'])

    def test_x_content_type_options_nosniff_present(self):
        """16. X-Content-Type-Options: nosniff header is present."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res['X-Content-Type-Options'], 'nosniff')

    def test_private_no_store_caching_headers_present(self):
        """17. Cache-Control: private, no-store headers are present."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertIn('private', res['Cache-Control'])
        self.assertIn('no-store', res['Cache-Control'])
        self.assertEqual(res['Pragma'], 'no-cache')

    def test_file_content_is_streamed_chunked(self):
        """18. File is streamed chunked without loading entire payload into RAM at once."""
        self.client.login(username='download_alice', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertTrue(isinstance(res, FileResponse))
        self.assertTrue(res.streaming)
        chunks = list(res.streaming_content)
        self.assertEqual(b''.join(chunks), self.valid_pdf_bytes)

    def test_unsupported_http_methods_rejected(self):
        """19. Only GET and HEAD methods are accepted; POST, PUT, DELETE return 405."""
        self.client.login(username='download_alice', password=self.password)
        url = reverse('documents:download', args=[self.alice_doc.id])

        # HEAD allowed (HTTP 200)
        res_head = self.client.head(url)
        self.assertEqual(res_head.status_code, 200)

        # POST rejected (HTTP 405)
        res_post = self.client.post(url)
        self.assertEqual(res_post.status_code, 405)

        # DELETE rejected (HTTP 405)
        res_delete = self.client.delete(url)
        self.assertEqual(res_delete.status_code, 405)

        # PUT rejected (HTTP 405)
        res_put = self.client.put(url)
        self.assertEqual(res_put.status_code, 405)

    # -------------------------------------------------------------------------
    # 4. UI Actions & Service Layer Grantor Validation
    # -------------------------------------------------------------------------
    def test_download_action_rendered_for_authorized_users_in_templates(self):
        """20. Templates render download action for authorized users."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        # Charlie (READ) views detail page: download button present
        self.client.login(username='download_charlie', password=self.password)
        res_detail = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res_detail.status_code, 200)
        self.assertContains(res_detail, reverse('documents:download', args=[self.alice_doc.id]))

        # Charlie views list page: download action present
        res_list = self.client.get(reverse('documents:list'))
        self.assertEqual(res_list.status_code, 200)
        self.assertContains(res_list, reverse('documents:download', args=[self.alice_doc.id]))

    def test_service_grant_permission_enforces_owner_authorization(self):
        """21. Non-owner attempting PermissionService.grant_permission raises PermissionDenied."""
        with self.assertRaises(PermissionDenied):
            PermissionService.grant_permission(
                actor=self.viewer_charlie,
                document=self.alice_doc,
                target_user=self.viewer_david,
                permission_type=PermissionType.READ
            )

    def test_service_revoke_permission_enforces_owner_authorization(self):
        """22. Non-owner attempting PermissionService.revoke_permission raises PermissionDenied."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )
        with self.assertRaises(PermissionDenied):
            PermissionService.revoke_permission(
                actor=self.viewer_david,
                document=self.alice_doc,
                target_user=self.viewer_charlie
            )
