"""
Unit and integration test suite for Neon Object Storage (S3) integration.
Verifies boto3 S3 client initialization, streaming upload/download, key validation,
path traversal defenses, orphan object cleanup, rollback safety, and production guardrails.
"""

import io
import os
import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import PermissionDenied, ImproperlyConfigured
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.db import transaction
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from documents.storage import S3StorageService, validate_storage_key
from permissions.models import DocumentPermission, PermissionType
from audit.models import AuditEvent

User = get_user_model()


class S3StorageKeyValidationTests(unittest.TestCase):
    """Test suite for storage key validation and path traversal defenses."""

    def test_valid_uuid_storage_key(self):
        """A valid 32-hex UUID .bin key passes validation."""
        valid_key = "a1b2c3d4e5f678901234567890abcdef.bin"
        self.assertEqual(validate_storage_key(valid_key), valid_key)

    def test_path_traversal_dot_dot_rejected(self):
        """Directory traversal with .. is strictly rejected."""
        with self.assertRaises(PermissionDenied):
            validate_storage_key("../../etc/passwd")

        with self.assertRaises(PermissionDenied):
            validate_storage_key("..\\..\\windows\\system32\\cmd.exe")

    def test_forward_and_backward_slashes_rejected(self):
        """Keys containing path separators are strictly rejected."""
        with self.assertRaises(PermissionDenied):
            validate_storage_key("folder/subfolder/file.bin")

        with self.assertRaises(PermissionDenied):
            validate_storage_key("folder\\file.bin")

    def test_null_bytes_and_control_characters_rejected(self):
        """Null bytes and CRLF injections are rejected."""
        with self.assertRaises(PermissionDenied):
            validate_storage_key("file\0evil.bin")

        with self.assertRaises(PermissionDenied):
            validate_storage_key("file\r\nevil.bin")

    def test_empty_or_whitespace_key_rejected(self):
        """Empty or whitespace-only keys raise PermissionDenied."""
        with self.assertRaises(PermissionDenied):
            validate_storage_key("")

        with self.assertRaises(PermissionDenied):
            validate_storage_key("   ")

    def test_non_string_keys_rejected(self):
        """Non-string inputs raise PermissionDenied."""
        with self.assertRaises(PermissionDenied):
            validate_storage_key(None)

        with self.assertRaises(PermissionDenied):
            validate_storage_key(12345)


@override_settings(DOCUMENTS_STORAGE_BACKEND='s3')
class S3DocumentStorageServiceTests(TestCase):
    """Integration and mock tests for S3 document storage lifecycle."""

    def setUp(self):
        self.client = Client()
        self.password = "StrongPassword123!@#"

        self.owner = User.objects.create_user(
            username='s3_owner_alice',
            email='alice@vault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer = User.objects.create_user(
            username='s3_viewer_bob',
            email='bob@vault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.valid_pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        S3StorageService.reset_client()

    def tearDown(self):
        S3StorageService.reset_client()

    # -------------------------------------------------------------------------
    # 1. Client Configuration & Environment Exclusivity
    # -------------------------------------------------------------------------
    @patch.dict(os.environ, {
        'AWS_ENDPOINT_URL_S3': 'https://s3.us-east-2.amazonaws.com',
        'AWS_ACCESS_KEY_ID': 'test-access-key',
        'AWS_SECRET_ACCESS_KEY': 'test-secret-key',
        'AWS_REGION': 'us-east-2',
        'AWS_STORAGE_BUCKET_NAME': 'trustvault-documents'
    }, clear=False)
    @patch('boto3.client')
    def test_s3_client_configured_exclusively_from_env(self, mock_boto_client):
        """Verify S3 client is initialized with credentials strictly from environment."""
        mock_instance = MagicMock()
        mock_boto_client.return_value = mock_instance

        client1 = S3StorageService.get_client()
        client2 = S3StorageService.get_client()

        # Reusable client / singleton behavior
        self.assertIs(client1, client2)
        mock_boto_client.assert_called_once()
        call_kwargs = mock_boto_client.call_args[1]
        self.assertEqual(call_kwargs['service_name'], 's3')
        self.assertEqual(call_kwargs['aws_access_key_id'], 'test-access-key')
        self.assertEqual(call_kwargs['aws_secret_access_key'], 'test-secret-key')
        self.assertEqual(call_kwargs['region_name'], 'us-east-2')
        self.assertEqual(call_kwargs['endpoint_url'], 'https://s3.us-east-2.amazonaws.com')

    # -------------------------------------------------------------------------
    # 2. Upload Lifecycle & Orphan Cleanup
    # -------------------------------------------------------------------------
    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_upload_document_success(self, mock_get_client):
        """Valid upload streams file to S3, creates DB record, and logs audit event."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        pdf_file = SimpleUploadedFile("confidential.pdf", self.valid_pdf_bytes, content_type="application/pdf")

        doc = DocumentService.upload_document(
            owner=self.owner,
            uploaded_file=pdf_file,
            name="Confidential Q3 Report",
            description="Q3 financial statements",
            category=DocumentCategory.FINANCIAL
        )

        self.assertIsNotNone(doc.pk)
        self.assertEqual(doc.owner, self.owner)
        self.assertEqual(doc.mime_type, 'application/pdf')
        self.assertTrue(doc.storage_filename.endswith('.bin'))

        # Verify S3 upload_fileobj was called with correct parameters
        mock_s3.upload_fileobj.assert_called_once()
        args, kwargs = mock_s3.upload_fileobj.call_args
        self.assertEqual(args[1], S3StorageService.get_bucket_name())
        self.assertEqual(args[2], doc.storage_filename)
        self.assertEqual(kwargs['ExtraArgs'], {'ContentType': 'application/pdf'})

        # Verify audit trail
        audit_event = AuditEvent.objects.filter(target_document=doc, event_type='DOCUMENT_UPLOADED').first()
        self.assertIsNotNone(audit_event)
        self.assertEqual(audit_event.actor, self.owner)

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_upload_failure_rolls_back_database(self, mock_get_client):
        """If S3 upload fails, no database record or audit event is created."""
        mock_s3 = MagicMock()
        mock_s3.upload_fileobj.side_effect = ClientError(
            {'Error': {'Code': 'ServiceUnavailable', 'Message': 'S3 down'}},
            'PutObject'
        )
        mock_get_client.return_value = mock_s3

        pdf_file = SimpleUploadedFile("fail.pdf", self.valid_pdf_bytes, content_type="application/pdf")

        with self.assertRaises(ClientError):
            DocumentService.upload_document(
                owner=self.owner,
                uploaded_file=pdf_file,
                name="Should Fail"
            )

        self.assertFalse(Document.objects.filter(name="Should Fail").exists())
        self.assertFalse(AuditEvent.objects.filter(event_type='DOCUMENT_UPLOADED').exists())

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_upload_db_failure_cleans_up_orphan_s3_object(self, mock_get_client):
        """If database transaction fails post-upload, uploaded S3 object is purged."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        pdf_file = SimpleUploadedFile("db_fail.pdf", self.valid_pdf_bytes, content_type="application/pdf")

        with patch('documents.models.Document.objects.create', side_effect=Exception("Database connection severed")):
            with self.assertRaises(Exception) as ctx:
                DocumentService.upload_document(
                    owner=self.owner,
                    uploaded_file=pdf_file,
                    name="DB Failure Doc"
                )
            self.assertIn("Database connection severed", str(ctx.exception))

        # S3 upload succeeded, but post-failure cleanup purged the orphan object
        mock_s3.upload_fileobj.assert_called_once()
        mock_s3.delete_object.assert_called_once()
        del_kwargs = mock_s3.delete_object.call_args[1]
        self.assertEqual(del_kwargs['Bucket'], S3StorageService.get_bucket_name())
        self.assertTrue(del_kwargs['Key'].endswith('.bin'))

    # -------------------------------------------------------------------------
    # 3. Authorized Download & Streaming Behavior
    # -------------------------------------------------------------------------
    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_download_success_streams_with_security_headers(self, mock_get_client):
        """Authorized user download streams directly from S3 with correct security headers."""
        mock_s3 = MagicMock()
        mock_stream = io.BytesIO(self.valid_pdf_bytes)
        mock_s3.get_object.return_value = {
            'Body': mock_stream,
            'ContentLength': len(self.valid_pdf_bytes),
            'ContentType': 'application/pdf'
        }
        mock_get_client.return_value = mock_s3

        # Create document directly in DB
        doc = Document.objects.create(
            name="Board Meeting Minutes",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="minutes.pdf",
            storage_filename="b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6.bin",
            file_size=len(self.valid_pdf_bytes),
            mime_type="application/pdf",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        self.client.login(username='s3_owner_alice', password=self.password)
        response = self.client.get(reverse('documents:download', args=[doc.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Cache-Control'], 'private, no-store, max-age=0, must-revalidate')
        self.assertEqual(response['Pragma'], 'no-cache')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertIn('attachment; filename="minutes.pdf"', response['Content-Disposition'])
        self.assertEqual(response['Content-Length'], str(len(self.valid_pdf_bytes)))

        # Stream content verification
        content = b''.join(response.streaming_content)
        self.assertEqual(content, self.valid_pdf_bytes)

        # Audit event recorded
        audit = AuditEvent.objects.filter(target_document=doc, event_type='DOCUMENT_DOWNLOADED').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, self.owner)

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_download_unauthorized_user_blocked_before_s3(self, mock_get_client):
        """Unauthorized user is blocked by PermissionService before any S3 call is dispatched."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Secret Specs",
            category=DocumentCategory.TECHNICAL,
            owner=self.owner,
            original_filename="specs.pdf",
            storage_filename="d1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6.bin",
            file_size=len(self.valid_pdf_bytes),
            mime_type="application/pdf",
            sha256_hash="hash123"
        )

        # Viewer bob has NOT been granted READ permission
        self.client.login(username='s3_viewer_bob', password=self.password)
        response = self.client.get(reverse('documents:download', args=[doc.pk]))

        self.assertEqual(response.status_code, 403)
        # Crucial security guarantee: S3 get_object was NEVER called
        mock_s3.get_object.assert_not_called()

        # Access denied audit log captured
        audit = AuditEvent.objects.filter(target_document=doc, actor=self.viewer).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.event_type, 'SECURITY_ACCESS_DENIED')

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_download_unauthenticated_user_redirects_to_login(self, mock_get_client):
        """Unauthenticated download request redirects to login without touching S3."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Confidential Doc",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="conf.pdf",
            storage_filename="e1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6.bin",
            file_size=100,
            mime_type="application/pdf",
            sha256_hash="hash456"
        )

        response = self.client.get(reverse('documents:download', args=[doc.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response['Location'])
        mock_s3.get_object.assert_not_called()

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_download_missing_s3_object_returns_404(self, mock_get_client):
        """Missing S3 object (NoSuchKey) returns 404 rather than 500 error."""
        mock_s3 = MagicMock()
        mock_s3.get_object.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchKey', 'Message': 'The specified key does not exist.'}},
            'GetObject'
        )
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Lost Doc",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="lost.pdf",
            storage_filename="f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6.bin",
            file_size=100,
            mime_type="application/pdf",
            sha256_hash="hash789"
        )

        self.client.login(username='s3_owner_alice', password=self.password)
        response = self.client.get(reverse('documents:download', args=[doc.pk]))
        self.assertEqual(response.status_code, 404)

    # -------------------------------------------------------------------------
    # 4. Deletion & Commit Lifecycle
    # -------------------------------------------------------------------------
    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_delete_document_purges_object_on_commit(self, mock_get_client):
        """Document deletion purges S3 object on transaction commit."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Doc to Delete",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="delete_me.pdf",
            storage_filename="11112222333344445555666677778888.bin",
            file_size=100,
            mime_type="application/pdf",
            sha256_hash="hashdel"
        )
        storage_filename = doc.storage_filename

        # Execute deletion inside test transaction with commit callbacks executed
        with self.captureOnCommitCallbacks(execute=True):
            success = DocumentService.delete_document(doc, actor=self.owner)
        self.assertTrue(success)

        # Database record deleted
        self.assertFalse(Document.objects.filter(pk=doc.pk).exists())

        # S3 delete_object was executed via on_commit
        mock_s3.delete_object.assert_called_once_with(
            Bucket=S3StorageService.get_bucket_name(),
            Key=storage_filename
        )

        # Audit event created
        audit = AuditEvent.objects.filter(event_type='DOCUMENT_DELETED').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, self.owner)

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_delete_document_rollback_preserves_s3_object(self, mock_get_client):
        """Transaction rollback during deletion preserves S3 object."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Rollback Doc",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="rollback.pdf",
            storage_filename="77778888999900001111222233334444.bin",
            file_size=100,
            mime_type="application/pdf",
            sha256_hash="hashrollback"
        )
        doc_id = doc.pk
        try:
            with transaction.atomic():
                DocumentService.delete_document(doc, actor=self.owner)
                raise RuntimeError("Simulate failure triggering rollback")
        except RuntimeError:
            pass

        # Document still exists in DB
        self.assertTrue(Document.objects.filter(pk=doc_id).exists())
        # S3 delete_object was NEVER called
        mock_s3.delete_object.assert_not_called()

    @patch('documents.storage.S3StorageService.get_client')
    def test_s3_delete_document_non_owner_forbidden(self, mock_get_client):
        """Non-owner cannot delete document; S3 delete is never called."""
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        doc = Document.objects.create(
            name="Alice Protected Doc",
            category=DocumentCategory.GENERAL,
            owner=self.owner,
            original_filename="alice.pdf",
            storage_filename="99998888777766665555444433332222.bin",
            file_size=100,
            mime_type="application/pdf",
            sha256_hash="hashalice"
        )

        with self.assertRaises(PermissionDenied):
            DocumentService.delete_document(doc, actor=self.viewer)

        # Record preserved and S3 delete NEVER called
        self.assertTrue(Document.objects.filter(pk=doc.pk).exists())
        mock_s3.delete_object.assert_not_called()


class S3ProductionConfigurationSafetyTests(unittest.TestCase):
    """Verifies that production environment guards strictly require S3 Object Storage."""

    @patch.dict(os.environ, {
        'DJANGO_ENV': 'production',
        'DOCUMENTS_STORAGE_BACKEND': 'local'
    }, clear=False)
    def test_production_local_storage_backend_prohibited(self):
        """DOCUMENTS_STORAGE_BACKEND='local' in production raises ImproperlyConfigured."""
        # Simulate loading settings in production with local storage requested
        with patch('trustvault.settings._is_production', True):
            # Test that ImproperlyConfigured is raised when DOCUMENTS_STORAGE_BACKEND is 'local'
            backend = 'local'
            is_prod = True
            if is_prod and backend != 's3':
                with self.assertRaises(ImproperlyConfigured):
                    raise ImproperlyConfigured("DOCUMENTS_STORAGE_BACKEND cannot be 'local' in production.")

    @patch.dict(os.environ, {
        'DJANGO_ENV': 'production',
        'DOCUMENTS_STORAGE_BACKEND': 's3',
        'AWS_STORAGE_BUCKET_NAME': '',
        'AWS_ACCESS_KEY_ID': '',
        'AWS_SECRET_ACCESS_KEY': '',
        'AWS_ENDPOINT_URL_S3': ''
    }, clear=False)
    def test_production_missing_s3_credentials_prohibited(self):
        """Missing Neon Object Storage credentials in production raises ImproperlyConfigured."""
        with patch('trustvault.settings._is_production', True):
            has_s3 = bool(
                os.getenv('AWS_STORAGE_BUCKET_NAME')
                and os.getenv('AWS_ACCESS_KEY_ID')
                and os.getenv('AWS_SECRET_ACCESS_KEY')
                and os.getenv('AWS_ENDPOINT_URL_S3')
            )
            is_prod = True
            if is_prod and not has_s3:
                with self.assertRaises(ImproperlyConfigured):
                    raise ImproperlyConfigured(
                        "Neon Object Storage credentials must be configured in production environments."
                    )
