"""
Comprehensive automated test suite for Phase 04: Document Permission Engine & Centralized Authorization.
Covers:
  - Document ownership authority (read, edit, delete, manage permissions).
  - READ-only permission grants (metadata view only, edit/delete blocked).
  - EDIT permission grants (read + edit allowed, delete/manage blocked).
  - Default-deny evaluation for unassigned users.
  - Strict administrator boundary (no automatic content access).
  - Anonymous request restrictions.
  - Database uniqueness constraints and permission integrity validation.
  - IDOR and parameter tampering defenses.
"""

import os
from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError, PermissionDenied
from django.db import IntegrityError
from django.contrib.auth import get_user_model
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService

User = get_user_model()


class DocumentPermissionEngineTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.password = "StrongPass123!@#"

        # Test users
        self.owner_alice = User.objects.create_user(
            username='alice_owner',
            email='alice@vault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_bob = User.objects.create_user(
            username='bob_viewer',
            email='bob@vault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_charlie = User.objects.create_user(
            username='charlie_viewer',
            email='charlie@vault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.owner_david = User.objects.create_user(
            username='david_owner',
            email='david@vault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.admin_eve = User.objects.create_user(
            username='eve_admin',
            email='eve@vault.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        # Create Alice's document
        pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        self.alice_doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice_vault.pdf", pdf_bytes, content_type="application/pdf"),
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
    # 1. Document Ownership Authority
    # -------------------------------------------------------------------------
    def test_owner_can_read_own_document(self):
        """1. Owner can read their own document."""
        self.assertTrue(PermissionService.can_read(self.owner_alice, self.alice_doc))
        self.assertEqual(PermissionService.get_effective_permission(self.owner_alice, self.alice_doc), 'OWNER')

        self.client.login(username='alice_owner', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)

    def test_owner_can_edit_own_document(self):
        """2. Owner can edit their own document."""
        self.assertTrue(PermissionService.can_edit(self.owner_alice, self.alice_doc))

        self.client.login(username='alice_owner', password=self.password)
        res = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Updated Alice Strategy',
            'category': DocumentCategory.TECHNICAL,
            'description': 'Updated by owner',
        })
        self.assertEqual(res.status_code, 302)
        self.alice_doc.refresh_from_db()
        self.assertEqual(self.alice_doc.name, 'Updated Alice Strategy')

    def test_owner_can_delete_own_document(self):
        """3. Owner can delete their own document."""
        self.assertTrue(PermissionService.can_delete(self.owner_alice, self.alice_doc))

        self.client.login(username='alice_owner', password=self.password)
        res = self.client.post(reverse('documents:delete', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 302)
        self.assertFalse(Document.objects.filter(pk=self.alice_doc.id).exists())

    def test_owner_can_manage_permissions(self):
        """4. Owner can manage their own document permissions."""
        self.assertTrue(PermissionService.can_manage_permissions(self.owner_alice, self.alice_doc))

    # -------------------------------------------------------------------------
    # 2. READ-Only Permission Semantics
    # -------------------------------------------------------------------------
    def test_read_user_can_read_authorized_document(self):
        """5. READ user can read an authorized document."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.assertTrue(PermissionService.can_read(self.viewer_bob, self.alice_doc))
        self.assertEqual(PermissionService.get_effective_permission(self.viewer_bob, self.alice_doc), 'READ')

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'Read Only')

    def test_read_user_cannot_edit_document(self):
        """6. READ user cannot edit the document (HTTP 403)."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.assertFalse(PermissionService.can_edit(self.viewer_bob, self.alice_doc))

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Tampered by Bob',
            'category': DocumentCategory.GENERAL,
        })
        self.assertEqual(res.status_code, 403)
        self.alice_doc.refresh_from_db()
        self.assertEqual(self.alice_doc.name, "Alice Confidential Strategy")

    def test_read_user_cannot_delete_document(self):
        """7. READ user cannot delete the document (HTTP 403)."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.assertFalse(PermissionService.can_delete(self.viewer_bob, self.alice_doc))

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.post(reverse('documents:delete', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.alice_doc.id).exists())

    def test_read_user_cannot_manage_permissions(self):
        """8. READ user cannot manage permissions."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.assertFalse(PermissionService.can_manage_permissions(self.viewer_bob, self.alice_doc))

    # -------------------------------------------------------------------------
    # 3. EDIT Permission Semantics
    # -------------------------------------------------------------------------
    def test_edit_user_can_read_authorized_document(self):
        """9. EDIT user can read the authorized document (EDIT includes READ)."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.assertTrue(PermissionService.can_read(self.viewer_bob, self.alice_doc))
        self.assertEqual(PermissionService.get_effective_permission(self.viewer_bob, self.alice_doc), 'EDIT')

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, 'Edit Access')

    def test_edit_user_can_edit_authorized_document_metadata(self):
        """10. EDIT user can edit authorized document metadata."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.assertTrue(PermissionService.can_edit(self.viewer_bob, self.alice_doc))

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Collaboratively Edited by Bob',
            'category': DocumentCategory.HR,
            'description': 'Bob updated the metadata successfully.',
        })
        self.assertEqual(res.status_code, 302)
        self.alice_doc.refresh_from_db()
        self.assertEqual(self.alice_doc.name, 'Collaboratively Edited by Bob')
        self.assertEqual(self.alice_doc.category, DocumentCategory.HR)

    def test_edit_user_cannot_delete_document(self):
        """11. EDIT user cannot delete the document (HTTP 403)."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.assertFalse(PermissionService.can_delete(self.viewer_bob, self.alice_doc))

        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.post(reverse('documents:delete', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.alice_doc.id).exists())

    def test_edit_user_cannot_manage_permissions(self):
        """12. EDIT user cannot manage permissions."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.assertFalse(PermissionService.can_manage_permissions(self.viewer_bob, self.alice_doc))

    # -------------------------------------------------------------------------
    # 4. Default-Deny & Unassigned Users
    # -------------------------------------------------------------------------
    def test_unassigned_user_cannot_read_document(self):
        """13. Unassigned user cannot read another user's document (HTTP 403)."""
        self.assertFalse(PermissionService.can_read(self.viewer_charlie, self.alice_doc))
        self.assertIsNone(PermissionService.get_effective_permission(self.viewer_charlie, self.alice_doc))

        self.client.login(username='charlie_viewer', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)

    def test_unassigned_user_cannot_edit_document(self):
        """14. Unassigned user cannot edit another user's document (HTTP 403)."""
        self.assertFalse(PermissionService.can_edit(self.viewer_charlie, self.alice_doc))

        self.client.login(username='charlie_viewer', password=self.password)
        res = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Hacked by Charlie',
            'category': DocumentCategory.GENERAL,
        })
        self.assertEqual(res.status_code, 403)

    def test_unassigned_user_cannot_delete_document(self):
        """15. Unassigned user cannot delete another user's document (HTTP 403)."""
        self.assertFalse(PermissionService.can_delete(self.viewer_charlie, self.alice_doc))

        self.client.login(username='charlie_viewer', password=self.password)
        res = self.client.post(reverse('documents:delete', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.alice_doc.id).exists())

    # -------------------------------------------------------------------------
    # 5. Administrator Privilege Boundary
    # -------------------------------------------------------------------------
    def test_admin_cannot_access_private_document_solely_by_role(self):
        """
        16. SECURITY RULE:
        Administrator cannot access private document contents solely because of their role.
        An admin without explicit ownership or permission is denied (HTTP 403).
        """
        self.assertFalse(PermissionService.can_read(self.admin_eve, self.alice_doc))
        self.assertFalse(PermissionService.can_edit(self.admin_eve, self.alice_doc))
        self.assertFalse(PermissionService.can_delete(self.admin_eve, self.alice_doc))

        self.client.login(username='eve_admin', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 403)

    def test_admin_can_access_document_only_if_independently_authorized(self):
        """
        17. Administrator can access a document only if independently authorized
        under the document permission policy (e.g. granted explicit permission).
        """
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.admin_eve,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.assertTrue(PermissionService.can_read(self.admin_eve, self.alice_doc))

        self.client.login(username='eve_admin', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)

    # -------------------------------------------------------------------------
    # 6. Anonymous Access
    # -------------------------------------------------------------------------
    def test_anonymous_user_cannot_access_protected_document_endpoints(self):
        """18. Anonymous users cannot access protected document endpoints."""
        self.assertFalse(PermissionService.can_read(None, self.alice_doc))
        self.assertFalse(PermissionService.can_edit(None, self.alice_doc))

        # Detail redirects to login
        res1 = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res1.status_code, 302)
        self.assertTrue(res1.url.startswith(reverse('accounts:login')))

        # Edit redirects to login
        res2 = self.client.get(reverse('documents:edit', args=[self.alice_doc.id]))
        self.assertEqual(res2.status_code, 302)

        # Delete redirects to login
        res3 = self.client.post(reverse('documents:delete', args=[self.alice_doc.id]))
        self.assertEqual(res3.status_code, 302)

    # -------------------------------------------------------------------------
    # 7. Permission Integrity & Defense Against Attacks
    # -------------------------------------------------------------------------
    def test_duplicate_document_user_permission_rejected(self):
        """19. Database constraint rejects duplicate document-user permission records."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        with self.assertRaises((IntegrityError, ValidationError)):
            # Attempt creating duplicate permission for same user on same document
            DocumentPermission.objects.create(
                document=self.alice_doc,
                user=self.viewer_bob,
                permission_type=PermissionType.EDIT,
                granted_by=self.owner_alice
            )

    def test_invalid_permission_type_rejected(self):
        """20. Invalid permission types are rejected by validation."""
        perm = DocumentPermission(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type='SUPERADMIN',
            granted_by=self.owner_alice
        )
        with self.assertRaises(ValidationError):
            perm.full_clean()

    def test_permission_assigned_to_one_user_does_not_authorize_another(self):
        """21. A permission assigned to User B never authorizes User C."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.assertTrue(PermissionService.can_read(self.viewer_bob, self.alice_doc))
        self.assertTrue(PermissionService.can_edit(self.viewer_bob, self.alice_doc))

        # Charlie must still be denied
        self.assertFalse(PermissionService.can_read(self.viewer_charlie, self.alice_doc))
        self.assertFalse(PermissionService.can_edit(self.viewer_charlie, self.alice_doc))

    def test_user_cannot_modify_permission_records_through_document_forms(self):
        """22. Injected permission fields into DocumentMetadataEditForm must be ignored."""
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.EDIT,
            granted_by=self.owner_alice
        )
        self.client.login(username='bob_viewer', password=self.password)
        # Attempt mass assignment / parameter tampering
        response = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Updated Title',
            'category': DocumentCategory.TECHNICAL,
            'permission_type': 'OWNER',
            'user': self.viewer_bob.id,
            'owner': self.viewer_bob.id,
        })
        self.assertEqual(response.status_code, 302)
        # Owner must NOT have changed
        self.alice_doc.refresh_from_db()
        self.assertEqual(self.alice_doc.owner, self.owner_alice)

    def test_ownership_cannot_be_changed_through_metadata_editing(self):
        """23. Ownership cannot be changed through metadata editing."""
        self.client.login(username='alice_owner', password=self.password)
        self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Transfer Attempt',
            'category': DocumentCategory.LEGAL,
            'owner': self.viewer_bob.id,
        })
        self.alice_doc.refresh_from_db()
        self.assertEqual(self.alice_doc.owner, self.owner_alice)

    def test_changing_document_uuid_cannot_bypass_authorization(self):
        """24. Changing document ID or requesting another document returns 403 Forbidden."""
        # David creates doc
        pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        david_doc = DocumentService.upload_document(
            owner=self.owner_david,
            uploaded_file=SimpleUploadedFile("david.pdf", pdf_bytes, content_type="application/pdf"),
            name="David Secret Doc"
        )
        self.created_files.append(DocumentService.get_protected_storage_path(david_doc.storage_filename))

        # Bob (has permission on Alice's doc) tries to access David's doc
        self.client.login(username='bob_viewer', password=self.password)
        res = self.client.get(reverse('documents:detail', args=[david_doc.id]))
        self.assertEqual(res.status_code, 403)

    # -------------------------------------------------------------------------
    # 8. Document Listing Filtering
    # -------------------------------------------------------------------------
    def test_get_accessible_documents_query(self):
        """Verify get_accessible_documents returns only owned or granted documents."""
        # Alice owns alice_doc
        # Grant Bob READ on alice_doc
        DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )

        # Bob queries accessible documents
        bob_docs = PermissionService.get_accessible_documents(self.viewer_bob)
        self.assertIn(self.alice_doc, bob_docs)

        # Charlie queries accessible documents -> empty
        charlie_docs = PermissionService.get_accessible_documents(self.viewer_charlie)
        self.assertNotIn(self.alice_doc, charlie_docs)

        # Eve (Admin) queries accessible documents -> empty unless granted
        eve_docs = PermissionService.get_accessible_documents(self.admin_eve)
        self.assertNotIn(self.alice_doc, eve_docs)
