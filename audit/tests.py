"""
Comprehensive automated test suite for Phase 07: Persistent Audit Trail & Document Activity Monitoring Engine.
Covers:
  - Event persistence across upload, download, update, delete, grant, update permission, and revoke.
  - Append-only immutability and tamper resistance at model and admin layers.
  - Role-based audit authorization (Administrator global access, Owner document activity, Viewer rejection).
  - Filtering, search, and pagination.
  - Transactional rollback integrity.
  - Data hygiene and sensitive attribute sanitization.
  - Historical snapshot retention upon entity deletion.
"""

import os
from datetime import timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.admin.sites import AdminSite
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError, PermissionDenied
from django.contrib.auth import get_user_model
from django.db import transaction
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType, AuditStatus
from audit.services import AuditService, AuditLoggingError
from audit.admin import AuditEventAdmin

User = get_user_model()


class PersistentAuditTrailEngineTests(TestCase):
    """
    Automated tests verifying Phase 07 Audit Trail functionality,
    transactional integrity, immutability, and access control.
    """

    def setUp(self):
        self.client = Client()
        self.password = "AuditSecurity123!@#"

        self.admin_user = User.objects.create_user(
            username='audit_admin',
            email='admin@audit.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        self.owner_alice = User.objects.create_user(
            username='audit_alice',
            email='alice@audit.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.owner_bob = User.objects.create_user(
            username='audit_bob',
            email='bob@audit.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_charlie = User.objects.create_user(
            username='audit_charlie',
            email='charlie@audit.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_david = User.objects.create_user(
            username='audit_david',
            email='david@audit.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        self.alice_doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice_paper.pdf", self.pdf_bytes, content_type="application/pdf"),
            name="Alice Confidential Audit Paper",
            description="Alice's confidential audit document.",
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
    # 1. Event Persistence Tests
    # -------------------------------------------------------------------------

    def test_01_upload_produces_persistent_audit_event(self):
        """01. Document upload records a persistent DOCUMENT_UPLOADED audit event."""
        event = AuditEvent.objects.filter(
            event_type=AuditEventType.DOCUMENT_UPLOADED,
            target_document=self.alice_doc
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.actor, self.owner_alice)
        self.assertEqual(event.actor_username, 'audit_alice')
        self.assertEqual(event.target_document_id_snapshot, self.alice_doc.pk)
        self.assertEqual(event.target_document_name_snapshot, "Alice Confidential Audit Paper")
        self.assertEqual(event.status, AuditStatus.SUCCESS)
        self.assertIn('original_filename', event.metadata)
        self.assertEqual(event.metadata['original_filename'], 'alice_paper.pdf')

    def test_02_download_produces_authorized_download_event(self):
        """02. Authorized document streaming produces a DOCUMENT_DOWNLOADED audit event."""
        # Grant READ to Charlie
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='audit_charlie', password=self.password)
        res = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.DOCUMENT_DOWNLOADED,
            target_document=self.alice_doc,
            actor=self.viewer_charlie
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.actor_username, 'audit_charlie')
        self.assertEqual(event.status, AuditStatus.SUCCESS)

    def test_03_metadata_edit_produces_audit_event(self):
        """03. Modifying document metadata produces a DOCUMENT_UPDATED audit event."""
        DocumentService.update_document_metadata(
            document=self.alice_doc,
            actor=self.owner_alice,
            name="Alice Revised Audit Paper",
            description="Updated description.",
            category=DocumentCategory.LEGAL
        )

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.DOCUMENT_UPDATED,
            target_document=self.alice_doc
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.actor, self.owner_alice)
        self.assertEqual(event.metadata.get('updated_name'), "Alice Revised Audit Paper")
        self.assertEqual(event.metadata.get('category'), DocumentCategory.LEGAL)

    def test_04_deletion_produces_event_with_preserved_snapshots(self):
        """04. Document deletion produces DOCUMENT_DELETED and preserves historical snapshot fields."""
        doc_id = self.alice_doc.pk
        doc_name = self.alice_doc.name

        DocumentService.delete_document(document=self.alice_doc, actor=self.owner_alice)

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.DOCUMENT_DELETED,
            target_document_id_snapshot=doc_id
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.actor, self.owner_alice)
        self.assertEqual(event.actor_username, 'audit_alice')
        self.assertEqual(event.target_document_id_snapshot, doc_id)
        self.assertEqual(event.target_document_name_snapshot, doc_name)
        self.assertIsNone(event.target_document)  # Nullified via on_delete=SET_NULL

    def test_05_permission_grant_produces_audit_event(self):
        """05. Granting document access produces a PERMISSION_GRANTED audit event."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.PERMISSION_GRANTED,
            target_document=self.alice_doc,
            target_user=self.viewer_charlie
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.actor, self.owner_alice)
        self.assertEqual(event.target_username, 'audit_charlie')
        self.assertEqual(event.new_permission, PermissionType.READ)

    def test_06_permission_update_records_previous_and_new_values(self):
        """06. Updating document access produces PERMISSION_UPDATED with old and new values."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        PermissionService.update_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            permission_id=perm.id,
            new_permission_type=PermissionType.EDIT
        )

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.PERMISSION_UPDATED,
            target_document=self.alice_doc,
            target_user=self.viewer_charlie
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.previous_permission, PermissionType.READ)
        self.assertEqual(event.new_permission, PermissionType.EDIT)

    def test_07_permission_revocation_produces_audit_event(self):
        """07. Revoking document access produces a PERMISSION_REVOKED audit event."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        PermissionService.revoke_permission_by_id(
            actor=self.owner_alice,
            document=self.alice_doc,
            permission_id=perm.id
        )

        event = AuditEvent.objects.filter(
            event_type=AuditEventType.PERMISSION_REVOKED,
            target_document=self.alice_doc,
            target_username='audit_charlie'
        ).first()

        self.assertIsNotNone(event)
        self.assertEqual(event.previous_permission, PermissionType.READ)
        self.assertEqual(event.target_username, 'audit_charlie')

    def test_08_events_survive_new_database_query_and_session(self):
        """08. Audit events survive new client sessions and persistent database queries."""
        # Query distinct fresh instances from DB
        events = list(AuditEvent.objects.all())
        self.assertTrue(len(events) >= 1)
        for ev in events:
            fresh_ev = AuditEvent.objects.get(uuid=ev.uuid)
            self.assertEqual(fresh_ev.pk, ev.pk)

    # -------------------------------------------------------------------------
    # 2. Role-Based Audit Access Authorization Tests
    # -------------------------------------------------------------------------

    def test_09_administrator_can_view_global_audit_trail(self):
        """09. Administrator can access global audit dashboard."""
        self.client.login(username='audit_admin', password=self.password)
        res = self.client.get(reverse('audit:trail'))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Global Audit Trail &amp; Activity Monitor")
        self.assertContains(res, "DOCUMENT_UPLOADED")

    def test_10_administrator_cannot_read_document_contents_through_audit(self):
        """10. Global audit interface does not leak document binary content or file download endpoints."""
        self.client.login(username='audit_admin', password=self.password)
        res = self.client.get(reverse('audit:trail'))
        self.assertEqual(res.status_code, 200)
        # Content does not contain actual binary stream or private storage path
        self.assertNotContains(res, "%PDF-1.4")
        self.assertNotContains(res, "protected_media")
        self.assertNotContains(res, "storage_filename")

    def test_11_owner_cannot_access_global_audit_dashboard(self):
        """11. Document Owner cannot access global audit dashboard (HTTP 403 Forbidden)."""
        self.client.login(username='audit_alice', password=self.password)
        res = self.client.get(reverse('audit:trail'))
        self.assertEqual(res.status_code, 403)

    def test_12_viewer_cannot_access_global_audit_dashboard(self):
        """12. Viewer cannot access global audit dashboard (HTTP 403 Forbidden)."""
        self.client.login(username='audit_charlie', password=self.password)
        res = self.client.get(reverse('audit:trail'))
        self.assertEqual(res.status_code, 403)

    def test_13_anonymous_user_cannot_access_audit_dashboard(self):
        """13. Anonymous user redirected to login when attempting to access audit trail."""
        res = self.client.get(reverse('audit:trail'))
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.url.startswith(reverse('accounts:login')))

    def test_14_document_owner_can_view_own_document_activity(self):
        """14. Document Owner can view activity log for their own document."""
        self.client.login(username='audit_alice', password=self.password)
        url = reverse('audit:document_activity', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Activity History: Alice Confidential Audit Paper")
        self.assertContains(res, "audit_alice")

    def test_15_document_owner_cannot_view_unrelated_owners_activity(self):
        """15. Document Owner cannot view activity history of another owner's document (HTTP 403)."""
        self.client.login(username='audit_bob', password=self.password)
        url = reverse('audit:document_activity', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 403)

    def test_16_viewer_cannot_view_document_activity(self):
        """16. Viewer cannot view document activity history (HTTP 403 Forbidden)."""
        self.client.login(username='audit_charlie', password=self.password)
        url = reverse('audit:document_activity', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 403)

    def test_17_anonymous_user_cannot_view_document_activity(self):
        """17. Anonymous user cannot access document activity endpoint (HTTP 302 redirect)."""
        url = reverse('audit:document_activity', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 302)

    # -------------------------------------------------------------------------
    # 3. Filtering, Search, and Pagination Tests
    # -------------------------------------------------------------------------

    def test_18_filter_audit_events_by_event_type(self):
        """18. Administrator can filter audit trail by specific event_type."""
        # Generate another event
        DocumentService.update_document_metadata(
            document=self.alice_doc,
            actor=self.owner_alice,
            name="Alice Paper V2",
            description="Desc",
            category=DocumentCategory.FINANCIAL
        )

        self.client.login(username='audit_admin', password=self.password)
        url = reverse('audit:trail') + f"?event_type={AuditEventType.DOCUMENT_UPDATED}"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Alice Paper V2")

    def test_19_filter_audit_events_by_actor(self):
        """19. Administrator can filter audit trail by actor username."""
        self.client.login(username='audit_admin', password=self.password)
        url = reverse('audit:trail') + "?actor=audit_alice"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "audit_alice")

    def test_20_filter_audit_events_by_date_range(self):
        """20. Administrator can filter audit trail by date range."""
        today_str = timezone.now().strftime('%Y-%m-%d')
        self.client.login(username='audit_admin', password=self.password)
        url = reverse('audit:trail') + f"?date_from={today_str}&date_to={today_str}"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Alice Confidential Audit Paper")

    def test_21_general_search_query_matches_document_or_actor(self):
        """21. Search query 'q' matches against document name snapshot and usernames."""
        self.client.login(username='audit_admin', password=self.password)
        url = reverse('audit:trail') + "?q=Confidential"
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Alice Confidential Audit Paper")

    def test_22_audit_trail_pagination(self):
        """22. Audit trail paginates records when count exceeds page limit."""
        # Bulk-create 30 dummy events directly via AuditService factory
        for i in range(30):
            AuditService.log_event(
                event_type=AuditEventType.DOCUMENT_DOWNLOADED,
                actor=self.viewer_charlie,
                target_document=self.alice_doc
            )

        self.client.login(username='audit_admin', password=self.password)
        res = self.client.get(reverse('audit:trail') + "?page=2")
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Showing page 2")

    # -------------------------------------------------------------------------
    # 4. Immutability & Tamper Resistance Tests
    # -------------------------------------------------------------------------

    def test_23_audit_event_save_on_existing_record_raises_validation_error(self):
        """23. AuditEvent.save() on existing record is blocked (append-only enforcement)."""
        event = AuditEvent.objects.first()
        self.assertIsNotNone(event)

        event.actor_username = "tampered_user"
        with self.assertRaises(ValidationError):
            event.save()

    def test_24_audit_event_delete_raises_validation_error(self):
        """24. AuditEvent.delete() raises ValidationError (tamper resistance)."""
        event = AuditEvent.objects.first()
        self.assertIsNotNone(event)

        with self.assertRaises(ValidationError):
            event.delete()

    def test_25_django_admin_disallows_add_permission(self):
        """25. AuditEventAdmin disallows adding new records through Django Admin."""
        admin_obj = AuditEventAdmin(AuditEvent, AdminSite())
        self.assertFalse(admin_obj.has_add_permission(None))

    def test_26_django_admin_disallows_change_permission(self):
        """26. AuditEventAdmin disallows modifying records through Django Admin."""
        admin_obj = AuditEventAdmin(AuditEvent, AdminSite())
        self.assertFalse(admin_obj.has_change_permission(None))

    def test_27_django_admin_disallows_delete_permission(self):
        """27. AuditEventAdmin disallows deleting records through Django Admin."""
        admin_obj = AuditEventAdmin(AuditEvent, AdminSite())
        self.assertFalse(admin_obj.has_delete_permission(None))

    # -------------------------------------------------------------------------
    # 5. Transactional Integrity & Rollback Tests
    # -------------------------------------------------------------------------

    def test_28_transaction_rollback_does_not_leave_false_audit_event(self):
        """28. Rolled-back document operation does not leave orphan audit event in database."""
        initial_event_count = AuditEvent.objects.count()

        try:
            with transaction.atomic():
                DocumentService.upload_document(
                    owner=self.owner_alice,
                    uploaded_file=SimpleUploadedFile("temp.pdf", self.pdf_bytes, content_type="application/pdf"),
                    name="Temporary Rollback Document",
                    category=DocumentCategory.FINANCIAL
                )
                # Force simulated failure within the same transaction
                raise RuntimeError("Simulated mid-transaction failure!")
        except RuntimeError:
            pass

        # Total event count must be identical (rolled back completely)
        self.assertEqual(AuditEvent.objects.count(), initial_event_count)
        self.assertFalse(AuditEvent.objects.filter(target_document_name_snapshot="Temporary Rollback Document").exists())

    def test_29_rolled_back_permission_grant_does_not_persist_event(self):
        """29. Rolled-back permission grant does not persist audit event."""
        initial_event_count = AuditEvent.objects.count()

        try:
            with transaction.atomic():
                PermissionService.grant_permission(
                    actor=self.owner_alice,
                    document=self.alice_doc,
                    target_user=self.viewer_david,
                    permission_type=PermissionType.READ
                )
                raise RuntimeError("Simulated transaction rollback!")
        except RuntimeError:
            pass

        self.assertEqual(AuditEvent.objects.count(), initial_event_count)
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_david).exists())

    # -------------------------------------------------------------------------
    # 6. Data Hygiene & Sensitive Attributes Tests
    # -------------------------------------------------------------------------

    def test_30_metadata_sanitization_strips_passwords_tokens_and_paths(self):
        """30. AuditService.sanitize_metadata strips passwords, tokens, cookies, and system paths."""
        dirty_meta = {
            'password': 'PlainTextSecretPassword123!',
            'user_token': 'eyJh...jwt_token',
            'session_id': 'sess_xyz123',
            'csrftoken': 'csrf_secret_token',
            'safe_param': 'clean_value',
            'file_path': 'C:\\secret\\path\\file.txt',
            'disk_location': 'f:\\Sheema\\protected_media\\secret.bin',
            'count': 42
        }

        clean = AuditService.sanitize_metadata(dirty_meta)

        self.assertIn('safe_param', clean)
        self.assertEqual(clean['safe_param'], 'clean_value')
        self.assertIn('count', clean)
        self.assertEqual(clean['count'], 42)

        # Sensitive keys must be absent
        self.assertNotIn('password', clean)
        self.assertNotIn('user_token', clean)
        self.assertNotIn('session_id', clean)
        self.assertNotIn('csrftoken', clean)
        self.assertNotIn('file_path', clean)
        self.assertNotIn('disk_location', clean)

    def test_31_historical_actor_preserved_if_user_deleted(self):
        """31. Historical actor_username snapshot remains preserved if User is deleted."""
        temp_user = User.objects.create_user(
            username='temp_actor',
            email='temp@test.local',
            password=self.password,
            role=User.Role.OWNER
        )

        event = AuditService.log_event(
            event_type=AuditEventType.DOCUMENT_UPDATED,
            actor=temp_user,
            target_document=self.alice_doc
        )

        self.assertEqual(event.actor, temp_user)
        self.assertEqual(event.actor_username, 'temp_actor')

        # Delete user
        temp_user.delete()

        event.refresh_from_db()
        self.assertIsNone(event.actor)  # Foreign key set to NULL
        self.assertEqual(event.actor_username, 'temp_actor')  # Snapshot preserved!

    def test_32_public_endpoints_cannot_mutate_audit_events(self):
        """32. Audit endpoints accept GET only; POST requests are rejected (HTTP 405)."""
        self.client.login(username='audit_admin', password=self.password)
        res_post = self.client.post(reverse('audit:trail'), {'event_type': 'FAKE_EVENT'})
        self.assertEqual(res_post.status_code, 405)
