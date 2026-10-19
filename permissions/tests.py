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

    # -------------------------------------------------------------------------
    # 9. Django Admin Privilege Boundary & Model Grantor Validation
    # -------------------------------------------------------------------------
    def test_non_owner_grantor_rejected_by_model_validation(self):
        """25. DocumentPermission raises ValidationError if grantor is not the document owner."""
        perm = DocumentPermission(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_david
        )
        with self.assertRaises(ValidationError) as ctx:
            perm.full_clean()
        self.assertIn("Only the document owner can grant permissions", str(ctx.exception))

    def test_admin_grantor_rejected_by_model_validation(self):
        """26. Administrator cannot be grantor of permissions for another user's document."""
        perm = DocumentPermission(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.admin_eve
        )
        with self.assertRaises(ValidationError) as ctx:
            perm.full_clean()
        self.assertIn("Only the document owner can grant permissions", str(ctx.exception))

    def test_admin_cannot_add_permission_via_django_admin(self):
        """27. Administrator cannot add DocumentPermission records via Django Admin."""
        self.admin_eve.is_superuser = True
        self.admin_eve.save()
        self.client.login(username='eve_admin', password=self.password)

        # GET /admin/permissions/documentpermission/add/
        res = self.client.get('/admin/permissions/documentpermission/add/')
        self.assertEqual(res.status_code, 403)

        # POST /admin/permissions/documentpermission/add/
        res_post = self.client.post('/admin/permissions/documentpermission/add/', {
            'document': self.alice_doc.id,
            'user': self.admin_eve.id,
            'permission_type': PermissionType.EDIT,
        })
        self.assertEqual(res_post.status_code, 403)
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.admin_eve).exists())

    def test_admin_cannot_change_or_delete_permission_via_django_admin(self):
        """28. Administrator cannot edit or delete DocumentPermission records via Django Admin."""
        perm = DocumentPermission.objects.create(
            document=self.alice_doc,
            user=self.viewer_bob,
            permission_type=PermissionType.READ,
            granted_by=self.owner_alice
        )
        self.admin_eve.is_superuser = True
        self.admin_eve.save()
        self.client.login(username='eve_admin', password=self.password)

        # Change attempt returns 403
        change_url = f'/admin/permissions/documentpermission/{perm.id}/change/'
        res_change = self.client.post(change_url, {
            'permission_type': PermissionType.EDIT,
        })
        self.assertEqual(res_change.status_code, 403)
        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.READ)

        # Delete attempt returns 403
        delete_url = f'/admin/permissions/documentpermission/{perm.id}/delete/'
        res_delete = self.client.post(delete_url, {'post': 'yes'})
        self.assertEqual(res_delete.status_code, 403)
        self.assertTrue(DocumentPermission.objects.filter(pk=perm.id).exists())

    def test_admin_cannot_modify_documents_via_django_admin(self):
        """29. Administrator cannot add, edit, or delete Document records via Django Admin."""
        self.admin_eve.is_superuser = True
        self.admin_eve.save()
        self.client.login(username='eve_admin', password=self.password)

        # Add document blocked (HTTP 403)
        res_add = self.client.get('/admin/documents/document/add/')
        self.assertEqual(res_add.status_code, 403)

        # Change document blocked (HTTP 403)
        res_change = self.client.post(f'/admin/documents/document/{self.alice_doc.id}/change/', {
            'name': 'Tampered Name',
            'owner': self.admin_eve.id,
        })
        self.assertEqual(res_change.status_code, 403)

        # Delete document blocked (HTTP 403)
        res_delete = self.client.post(f'/admin/documents/document/{self.alice_doc.id}/delete/', {'post': 'yes'})
        self.assertEqual(res_delete.status_code, 403)
        self.assertTrue(Document.objects.filter(pk=self.alice_doc.id).exists())


class DocumentSharingWorkflowTests(TestCase):
    """
    Automated security and functional test suite for Phase 06:
    Document Sharing & Access Revocation Engine.
    Covers:
      - Sharing workflow (owner grants READ/EDIT, validations, self-sharing, invalid users).
      - Permission updates (READ <-> EDIT, cross-document IDOR defense, unauthorized attempts).
      - Revocation workflow (owner revokes, method enforcement, CSRF, immediate access cutoff).
      - User lookup security (owner-only access, exclusion of inactive users and self, bounded results, no sensitive fields).
    """

    def setUp(self):
        self.client = Client()
        self.password = "SharingSecret123!@#"

        self.owner_alice = User.objects.create_user(
            username='share_alice',
            email='alice@share.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.owner_bob = User.objects.create_user(
            username='share_bob',
            email='bob@share.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_charlie = User.objects.create_user(
            username='share_charlie',
            email='charlie@share.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_david = User.objects.create_user(
            username='share_david',
            email='david@share.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_inactive = User.objects.create_user(
            username='share_inactive',
            email='inactive@share.local',
            password=self.password,
            role=User.Role.VIEWER,
            is_active=False
        )

        self.admin_eve = User.objects.create_user(
            username='share_eve',
            email='eve@share.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"
        self.alice_doc = DocumentService.upload_document(
            owner=self.owner_alice,
            uploaded_file=SimpleUploadedFile("alice_vault.pdf", pdf_bytes, content_type="application/pdf"),
            name="Alice Strategy Paper",
            description="Alice's confidential strategic document.",
            category=DocumentCategory.FINANCIAL
        )

        self.bob_doc = DocumentService.upload_document(
            owner=self.owner_bob,
            uploaded_file=SimpleUploadedFile("bob_vault.pdf", pdf_bytes, content_type="application/pdf"),
            name="Bob Blueprint",
            description="Bob's technical blueprint.",
            category=DocumentCategory.TECHNICAL
        )

        self.created_files = [
            DocumentService.get_protected_storage_path(self.alice_doc.storage_filename),
            DocumentService.get_protected_storage_path(self.bob_doc.storage_filename),
        ]

    def tearDown(self):
        for path in self.created_files:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # 1. Sharing Workflow
    # -------------------------------------------------------------------------
    def test_01_owner_can_grant_read_permission(self):
        """1. Document owner can grant READ access."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 302)
        self.assertRedirects(res, url)
        self.assertTrue(
            DocumentPermission.objects.filter(
                document=self.alice_doc,
                user=self.viewer_charlie,
                permission_type=PermissionType.READ,
                granted_by=self.owner_alice
            ).exists()
        )

    def test_02_owner_can_grant_edit_permission(self):
        """2. Document owner can grant EDIT access."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_david',
            'permission_type': PermissionType.EDIT,
        })
        self.assertEqual(res.status_code, 302)
        self.assertTrue(
            DocumentPermission.objects.filter(
                document=self.alice_doc,
                user=self.viewer_david,
                permission_type=PermissionType.EDIT,
                granted_by=self.owner_alice
            ).exists()
        )

    def test_03_unauthorized_owner_cannot_share_another_owners_document(self):
        """3. Unauthorized owner cannot share another owner's document."""
        self.client.login(username='share_bob', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 403)
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_charlie).exists())

    def test_04_viewer_cannot_share_documents(self):
        """4. Viewer cannot share documents."""
        self.client.login(username='share_charlie', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_david',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 403)

    def test_05_administrator_cannot_bypass_owner_restrictions(self):
        """5. Administrator cannot bypass owner restrictions to share document."""
        self.client.login(username='share_eve', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 403)
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_charlie).exists())

    def test_06_user_cannot_share_document_with_themselves(self):
        """6. User cannot share a document with themselves."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_alice',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "You cannot share a document with yourself.")
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.owner_alice).exists())

    def test_07_nonexistent_recipient_is_rejected(self):
        """7. Nonexistent recipient is rejected."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'nonexistent_ghost_user',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "does not exist")

    def test_08_inactive_recipient_is_rejected(self):
        """8. Inactive recipient is rejected."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_inactive',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "is inactive")
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_inactive).exists())

    def test_09_invalid_permission_level_is_rejected(self):
        """9. Invalid permission level is rejected."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])
        res = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': 'SUPER_ADMIN_INVALID',
        })
        self.assertEqual(res.status_code, 200)
        self.assertFalse(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_charlie).exists())

    def test_10_duplicate_sharing_handled_safely(self):
        """10. Duplicate sharing is handled safely (updates or preserves record)."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])

        # First grant
        res1 = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res1.status_code, 302)

        # Second grant with same permission
        res2 = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
        })
        self.assertEqual(res2.status_code, 302)

        # Exactly 1 permission record exists
        self.assertEqual(DocumentPermission.objects.filter(document=self.alice_doc, user=self.viewer_charlie).count(), 1)

    def test_11_recipient_cannot_be_assigned_permissions_through_manipulated_request_fields(self):
        """11. Recipient cannot be assigned permissions through manipulated request fields."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:manage', args=[self.alice_doc.id])

        # Attempt to tamper with granted_by and target document
        res = self.client.post(url, {
            'recipient_username': 'share_charlie',
            'permission_type': PermissionType.READ,
            'granted_by': self.owner_bob.id,
            'document': self.bob_doc.id,
        })
        self.assertEqual(res.status_code, 302)

        perm = DocumentPermission.objects.get(document=self.alice_doc, user=self.viewer_charlie)
        # Server forces granted_by to alice and document to alice_doc
        self.assertEqual(perm.granted_by, self.owner_alice)
        self.assertEqual(perm.document, self.alice_doc)

    # -------------------------------------------------------------------------
    # 2. Permission Updates
    # -------------------------------------------------------------------------
    def test_12_owner_can_change_read_to_edit(self):
        """12. Owner can change READ to EDIT."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:update', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(res.status_code, 302)

        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.EDIT)

    def test_13_owner_can_change_edit_to_read(self):
        """13. Owner can change EDIT to READ."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_david,
            permission_type=PermissionType.EDIT
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:update', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url, {'permission_type': PermissionType.READ})
        self.assertEqual(res.status_code, 302)

        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.READ)

    def test_14_non_owner_cannot_modify_permissions(self):
        """14. Non-owner cannot modify permissions."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_bob', password=self.password)
        url = reverse('permissions:update', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(res.status_code, 403)

        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.READ)

    def test_15_cross_document_permission_id_manipulation_is_rejected(self):
        """15. Cross-document permission ID manipulation is rejected."""
        # Charlie has permission on Bob's document
        bob_perm = PermissionService.grant_permission(
            actor=self.owner_bob,
            document=self.bob_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        # Alice logs in and attempts to update Bob's permission ID via Alice's document route
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:update', args=[self.alice_doc.id, bob_perm.id])
        res = self.client.post(url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(res.status_code, 403)

        bob_perm.refresh_from_db()
        self.assertEqual(bob_perm.permission_type, PermissionType.READ)

    def test_16_unauthorized_role_cannot_update_permissions(self):
        """16. Unauthorized role (Viewer, Admin) cannot update permissions."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        url = reverse('permissions:update', args=[self.alice_doc.id, perm.id])

        # Viewer attempt
        self.client.login(username='share_charlie', password=self.password)
        res_v = self.client.post(url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(res_v.status_code, 403)

        # Admin attempt
        self.client.login(username='share_eve', password=self.password)
        res_a = self.client.post(url, {'permission_type': PermissionType.EDIT})
        self.assertEqual(res_a.status_code, 403)

    # -------------------------------------------------------------------------
    # 3. Revocation Workflow
    # -------------------------------------------------------------------------
    def test_17_owner_can_revoke_access(self):
        """17. Owner can revoke access."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:revoke', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 302)
        self.assertFalse(DocumentPermission.objects.filter(pk=perm.id).exists())

    def test_18_non_owner_cannot_revoke_access(self):
        """18. Non-owner cannot revoke access."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_bob', password=self.password)
        url = reverse('permissions:revoke', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 403)
        self.assertTrue(DocumentPermission.objects.filter(pk=perm.id).exists())

    def test_19_revocation_uses_post(self):
        """19. Revocation uses POST; GET returns 405 Method Not Allowed."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:revoke', args=[self.alice_doc.id, perm.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 405)
        self.assertTrue(DocumentPermission.objects.filter(pk=perm.id).exists())

    def test_20_get_requests_cannot_mutate_permissions(self):
        """20. GET requests cannot mutate permissions."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)

        # GET on grant endpoint returns 405
        res_grant = self.client.get(reverse('permissions:grant', args=[self.alice_doc.id]))
        self.assertEqual(res_grant.status_code, 405)

        # GET on update endpoint returns 405
        res_update = self.client.get(reverse('permissions:update', args=[self.alice_doc.id, perm.id]))
        self.assertEqual(res_update.status_code, 405)

        # GET on revoke endpoint returns 405
        res_revoke = self.client.get(reverse('permissions:revoke', args=[self.alice_doc.id, perm.id]))
        self.assertEqual(res_revoke.status_code, 405)

        perm.refresh_from_db()
        self.assertEqual(perm.permission_type, PermissionType.READ)

    def test_21_csrf_protection_remains_enabled(self):
        """21. CSRF protection remains enabled for state-changing permission endpoints."""
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username='share_alice', password=self.password)

        # POST without CSRF token to grant endpoint fails with 403
        res = csrf_client.post(
            reverse('permissions:manage', args=[self.alice_doc.id]),
            {'recipient_username': 'share_charlie', 'permission_type': PermissionType.READ}
        )
        self.assertEqual(res.status_code, 403)

    def test_22_revoked_read_user_cannot_access_the_document(self):
        """22. Revoked READ user immediately loses document access."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        # Charlie accesses document successfully
        self.client.login(username='share_charlie', password=self.password)
        res_detail = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res_detail.status_code, 200)

        # Alice revokes permission
        PermissionService.revoke_permission_by_id(self.owner_alice, self.alice_doc, perm.id)

        # Charlie attempts access again immediately
        res_detail_revoked = self.client.get(reverse('documents:detail', args=[self.alice_doc.id]))
        self.assertEqual(res_detail_revoked.status_code, 403)

        res_download_revoked = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res_download_revoked.status_code, 403)

    def test_23_revoked_edit_user_cannot_edit_or_download(self):
        """23. Revoked EDIT user cannot edit or download."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_david,
            permission_type=PermissionType.EDIT
        )

        # Alice revokes David's permission
        PermissionService.revoke_permission_by_id(self.owner_alice, self.alice_doc, perm.id)

        self.client.login(username='share_david', password=self.password)

        # Edit blocked
        res_edit = self.client.post(reverse('documents:edit', args=[self.alice_doc.id]), {
            'name': 'Hacked Document Title',
            'category': DocumentCategory.LEGAL,
        })
        self.assertEqual(res_edit.status_code, 403)

        # Download blocked
        res_download = self.client.get(reverse('documents:download', args=[self.alice_doc.id]))
        self.assertEqual(res_download.status_code, 403)

    def test_24_revocation_does_not_delete_the_underlying_document(self):
        """24. Revocation does not delete the underlying document or storage file."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:revoke', args=[self.alice_doc.id, perm.id])
        res = self.client.post(url)
        self.assertEqual(res.status_code, 302)

        # Underlying document record is intact
        self.assertTrue(Document.objects.filter(pk=self.alice_doc.id).exists())

        # Physical file still exists
        storage_path = DocumentService.get_protected_storage_path(self.alice_doc.storage_filename)
        self.assertTrue(storage_path.exists())

    def test_25_repeated_revocation_is_handled_safely(self):
        """25. Repeated revocation is handled safely without error."""
        perm = PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:revoke', args=[self.alice_doc.id, perm.id])

        # First revocation
        res1 = self.client.post(url)
        self.assertEqual(res1.status_code, 302)

        # Second revocation of already-deleted permission
        res2 = self.client.post(url)
        self.assertEqual(res2.status_code, 302)

    # -------------------------------------------------------------------------
    # 4. User Lookup Security
    # -------------------------------------------------------------------------
    def test_26_anonymous_user_cannot_search_recipients(self):
        """26. Anonymous user cannot search recipients."""
        url = reverse('permissions:user_search', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.url.startswith(reverse('accounts:login')))

    def test_27_viewer_cannot_access_owner_only_lookup(self):
        """27. Viewer cannot access owner-only lookup."""
        self.client.login(username='share_charlie', password=self.password)
        url = reverse('permissions:user_search', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 403)

    def test_28_administrator_cannot_use_lookup_to_bypass_document_access_controls(self):
        """28. Administrator cannot use lookup to bypass document access controls."""
        self.client.login(username='share_eve', password=self.password)
        url = reverse('permissions:user_search', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 403)

    def test_29_inactive_accounts_are_excluded_from_lookup(self):
        """29. Inactive accounts are excluded from lookup results."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:user_search', args=[self.alice_doc.id]) + '?q=share_'
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        usernames = [u['username'] for u in data['results']]
        self.assertNotIn('share_inactive', usernames)
        self.assertNotIn('share_alice', usernames)  # Owner excluded from sharing with self

    def test_30_sensitive_account_fields_are_not_returned(self):
        """30. Sensitive account fields are not returned in lookup API."""
        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:user_search', args=[self.alice_doc.id])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        self.assertTrue(len(data['results']) > 0)
        for user_entry in data['results']:
            # Permitted safe fields only
            self.assertIn('id', user_entry)
            self.assertIn('username', user_entry)
            self.assertIn('role', user_entry)
            # Sensitive fields strictly absent
            self.assertNotIn('password', user_entry)
            self.assertNotIn('email', user_entry)
            self.assertNotIn('is_superuser', user_entry)
            self.assertNotIn('is_staff', user_entry)

    def test_31_search_result_count_is_bounded(self):
        """31. Search result count is bounded to prevent massive user enumeration."""
        # Create 25 additional active viewer accounts
        bulk_users = [
            User(username=f'bulk_viewer_{i}', email=f'bulk_{i}@test.local', role=User.Role.VIEWER)
            for i in range(25)
        ]
        User.objects.bulk_create(bulk_users)

        self.client.login(username='share_alice', password=self.password)
        url = reverse('permissions:user_search', args=[self.alice_doc.id]) + '?q=bulk_'
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)

        data = res.json()
        # Bound limit is 20
        self.assertLessEqual(len(data['results']), 20)

    # -------------------------------------------------------------------------
    # 5. Routing and UI Navigation Tests
    # -------------------------------------------------------------------------
    def test_32_document_share_redirect_view_routes_to_permissions_manage(self):
        """32. Document share convenience route redirects to permissions:manage."""
        self.client.login(username='share_alice', password=self.password)
        res = self.client.get(reverse('documents:share', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 302)
        self.assertRedirects(res, reverse('permissions:manage', args=[self.alice_doc.id]))

    def test_33_manage_page_renders_active_permissions_and_share_form(self):
        """33. Manage permissions page renders active permissions, UI actions, and share form."""
        PermissionService.grant_permission(
            actor=self.owner_alice,
            document=self.alice_doc,
            target_user=self.viewer_charlie,
            permission_type=PermissionType.READ
        )

        self.client.login(username='share_alice', password=self.password)
        res = self.client.get(reverse('permissions:manage', args=[self.alice_doc.id]))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Alice Strategy Paper")
        self.assertContains(res, "share_charlie")
        self.assertContains(res, "READ")
        self.assertContains(res, "Grant Access to a User")

