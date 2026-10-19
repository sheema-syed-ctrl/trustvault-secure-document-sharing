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
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from documents.validators import validate_file_upload, sanitize_filename

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
        response = self.client.post(reverse('documents:delete', args=[doc.id]))
        self.assertRedirects(response, reverse('documents:list'))

        # DB record removed
        self.assertFalse(Document.objects.filter(pk=doc.id).exists())
        # Disk file removed
        self.assertFalse(target_path.exists())
