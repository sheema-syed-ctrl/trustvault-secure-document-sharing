"""
Comprehensive automated test suite for Phase 09: Role-Specific Dashboards & Admin Monitoring.
Validates:
  - Central role-based dashboard dispatching (/dashboard/)
  - Strict server-side access control boundaries (/dashboard/admin/, /dashboard/owner/, /dashboard/viewer/)
  - Administrator system governance metrics and bounded activity feeds
  - Zero administrative bypass or leakage of private document files/downloads
  - Document Owner data isolation, category aggregation, and owner-scoped activity feeds
  - Viewer workspace access, READ vs EDIT permission distinctions, and action restrictions
  - Immediate consistency upon permission revocation
"""

import os
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType, AuditStatus
from audit.services import AuditService

User = get_user_model()


@override_settings(PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'])
class BaseDashboardTestCase(TestCase):
    """Common fixture setup for dashboard test suites."""

    def setUp(self):
        self.client = Client()
        self.password = "Secur3P@ssw0rd!2026"
        self.created_files = []

        # 1. Users across roles
        self.admin = User.objects.create_user(
            username='admin_marcus',
            email='marcus@trustvault.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        self.owner_1 = User.objects.create_user(
            username='owner_alyssa',
            email='alyssa@trustvault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.owner_2 = User.objects.create_user(
            username='owner_bryan',
            email='bryan@trustvault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_1 = User.objects.create_user(
            username='viewer_carla',
            email='carla@trustvault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.viewer_2 = User.objects.create_user(
            username='viewer_dan',
            email='dan@trustvault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

        self.inactive_user = User.objects.create_user(
            username='inactive_elena',
            email='elena@trustvault.local',
            password=self.password,
            role=User.Role.VIEWER,
            is_active=False
        )

        # 2. Upload documents
        pdf_content = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nxref\ntrailer\nstartxref\n%%EOF"

        # Owner 1 documents
        self.doc_fin = DocumentService.upload_document(
            owner=self.owner_1,
            uploaded_file=SimpleUploadedFile("q3_fin.pdf", pdf_content, content_type="application/pdf"),
            name="Q3 Financial Overview",
            description="Confidential quarterly earnings report",
            category=DocumentCategory.FINANCIAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_fin.storage_filename))

        self.doc_tech = DocumentService.upload_document(
            owner=self.owner_1,
            uploaded_file=SimpleUploadedFile("arch_spec.pdf", pdf_content, content_type="application/pdf"),
            name="Cloud Security Architecture",
            description="System topology & encryption boundaries",
            category=DocumentCategory.TECHNICAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_tech.storage_filename))

        self.doc_legal = DocumentService.upload_document(
            owner=self.owner_1,
            uploaded_file=SimpleUploadedFile("vendor_nda.pdf", pdf_content, content_type="application/pdf"),
            name="Vendor Mutual NDA",
            description="Standard legal confidentiality agreement",
            category=DocumentCategory.LEGAL
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_legal.storage_filename))

        # Owner 2 document
        self.doc_hr = DocumentService.upload_document(
            owner=self.owner_2,
            uploaded_file=SimpleUploadedFile("hiring_plan.pdf", pdf_content, content_type="application/pdf"),
            name="2026 Headcount Budget",
            description="HR confidential allocation",
            category=DocumentCategory.HR
        )
        self.created_files.append(DocumentService.get_protected_storage_path(self.doc_hr.storage_filename))

        # 3. Permissions
        # viewer_1 gets READ on doc_fin
        self.perm_read = PermissionService.grant_permission(
            actor=self.owner_1,
            document=self.doc_fin,
            target_user=self.viewer_1,
            permission_type=PermissionType.READ
        )

        # viewer_1 gets EDIT on doc_tech
        self.perm_edit = PermissionService.grant_permission(
            actor=self.owner_1,
            document=self.doc_tech,
            target_user=self.viewer_1,
            permission_type=PermissionType.EDIT
        )

        # viewer_2 gets READ on doc_hr (Owner 2's document)
        self.perm_owner2 = PermissionService.grant_permission(
            actor=self.owner_2,
            document=self.doc_hr,
            target_user=self.viewer_2,
            permission_type=PermissionType.READ
        )

    def tearDown(self):
        for path in self.created_files:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass


class DashboardRoutingTests(BaseDashboardTestCase):
    """Validates automatic role-based dispatching at /dashboard/."""

    def test_unauthenticated_user_redirected_to_login(self):
        """Unauthenticated GET /dashboard/ redirects to login URL."""
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_admin_dispatched_to_admin_dashboard(self):
        """Admin visiting /dashboard/ renders admin_dashboard.html."""
        self.client.login(username='admin_marcus', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/admin_dashboard.html')

    def test_owner_dispatched_to_owner_dashboard(self):
        """Document Owner visiting /dashboard/ renders owner_dashboard.html."""
        self.client.login(username='owner_alyssa', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/owner_dashboard.html')

    def test_viewer_dispatched_to_viewer_dashboard(self):
        """Viewer visiting /dashboard/ renders viewer_dashboard.html."""
        self.client.login(username='viewer_carla', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/viewer_dashboard.html')


class DashboardAccessControlTests(BaseDashboardTestCase):
    """Validates strict server-side access control boundaries on dedicated dashboard endpoints."""

    def test_unauthenticated_cannot_access_admin_dashboard(self):
        """Anonymous request to /dashboard/admin/ redirects to login."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_unauthenticated_cannot_access_owner_dashboard(self):
        """Anonymous request to /dashboard/owner/ redirects to login."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_unauthenticated_cannot_access_viewer_dashboard(self):
        """Anonymous request to /dashboard/viewer/ redirects to login."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('accounts:login'), response.url)

    def test_viewer_cannot_access_admin_dashboard_returns_403(self):
        """Viewer attempting to access /dashboard/admin/ receives HTTP 403 Forbidden."""
        self.client.login(username='viewer_carla', password=self.password)
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 403)

    def test_owner_cannot_access_admin_dashboard_returns_403(self):
        """Owner attempting to access /dashboard/admin/ receives HTTP 403 Forbidden."""
        self.client.login(username='owner_alyssa', password=self.password)
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_access_owner_dashboard_returns_403(self):
        """Viewer attempting to access /dashboard/owner/ receives HTTP 403 Forbidden."""
        self.client.login(username='viewer_carla', password=self.password)
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 403)

    def test_admin_can_access_admin_dashboard(self):
        """Admin accessing /dashboard/admin/ receives HTTP 200."""
        self.client.login(username='admin_marcus', password=self.password)
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

    def test_owner_can_access_owner_dashboard(self):
        """Owner accessing /dashboard/owner/ receives HTTP 200."""
        self.client.login(username='owner_alyssa', password=self.password)
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

    def test_viewer_can_access_viewer_dashboard(self):
        """Viewer accessing /dashboard/viewer/ receives HTTP 200."""
        self.client.login(username='viewer_carla', password=self.password)
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)


class AdminDashboardTests(BaseDashboardTestCase):
    """Validates metrics accuracy, audit oversight, and privacy boundaries for the Administrator dashboard."""

    def setUp(self):
        super().setUp()
        self.client.login(username='admin_marcus', password=self.password)

    def test_admin_metrics_user_counts_accurate(self):
        """Admin dashboard accurately computes active, inactive, total users, and role counts."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['total_users'], 6)
        self.assertEqual(context['active_users'], 5)
        self.assertEqual(context['inactive_users'], 1)
        self.assertEqual(context['admin_count'], 1)
        self.assertEqual(context['owner_count'], 2)
        self.assertEqual(context['viewer_count'], 3)

    def test_admin_metrics_document_and_permission_counts(self):
        """Admin dashboard accurately computes system-wide document and permission totals."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['total_documents'], 4)
        self.assertEqual(context['total_permissions'], 3)

    def test_admin_metrics_security_denials_accurate(self):
        """Admin dashboard accurately counts security access denied events."""
        # Create a security denial audit event
        AuditService.log_access_denied(
            actor=self.viewer_2,
            event_type='DOCUMENT_DOWNLOADED',
            document=self.doc_fin,
            reason="Unauthorized download attempt"
        )

        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['security_denial_count'], 1)
        self.assertEqual(len(response.context['recent_security_denials']), 1)
        self.assertContains(response, "Recent Security Access Denials")
        self.assertContains(response, "viewer_dan")

    def test_admin_dashboard_shows_recent_activity_feed(self):
        """Admin dashboard presents bounded recent activity feed."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertIn('recent_activity', context)
        self.assertLessEqual(len(context['recent_activity']), 10)

    def test_admin_dashboard_does_not_leak_unauthorized_download_links(self):
        """Admin dashboard never includes direct download URLs for private documents."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)

        # Confirm no document download link is presented on the admin dashboard
        download_url = reverse('documents:download', kwargs={'doc_id': self.doc_fin.pk})
        self.assertNotContains(response, download_url)

    def test_admin_dashboard_recent_users_bounded(self):
        """Recent users table contains at most 5 entries."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.context['recent_users']), 5)

    def test_admin_dashboard_security_denial_banner_absent_when_zero(self):
        """Security denial banner is absent when denial count is 0."""
        response = self.client.get(reverse('dashboard:admin'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['security_denial_count'], 0)
        self.assertNotContains(response, "Recent Security Access Denials")


class OwnerDashboardTests(BaseDashboardTestCase):
    """Validates document isolation, category aggregation, and owner-scoped activity feeds."""

    def setUp(self):
        super().setUp()
        self.client.login(username='owner_alyssa', password=self.password)

    def test_owner_metrics_isolated_to_own_documents(self):
        """Owner Alyssa only sees her 3 documents; Owner Bryan's document is excluded."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['total_documents'], 3)
        self.assertEqual(Document.objects.count(), 4)  # 4 total in database

    def test_owner_shared_documents_count_accurate(self):
        """Owner Alyssa has 2 shared documents (doc_fin, doc_tech); doc_legal is unshared."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['shared_count'], 2)

    def test_owner_active_permissions_breakdown(self):
        """Owner Alyssa has 2 active permissions (1 READ, 1 EDIT); Bryan's grant is excluded."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['active_permissions'], 2)
        self.assertEqual(context['read_permissions_count'], 1)
        self.assertEqual(context['edit_permissions_count'], 1)

    def test_owner_category_metrics_accurate(self):
        """Owner Alyssa's category metrics report exact counts for all 5 categories."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        cat_map = {item['code']: item['count'] for item in response.context['category_metrics']}
        self.assertEqual(cat_map['FINANCIAL'], 1)
        self.assertEqual(cat_map['TECHNICAL'], 1)
        self.assertEqual(cat_map['LEGAL'], 1)
        self.assertEqual(cat_map['HR'], 0)  # HR is owned by Bryan!
        self.assertEqual(cat_map['GENERAL'], 0)

    def test_owner_recent_documents_bounded_and_annotated(self):
        """Recent documents are bounded to 5 and annotated with active share count."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        recent_docs = response.context['recent_documents']
        self.assertEqual(len(recent_docs), 3)

        doc_names = [d.name for d in recent_docs]
        self.assertIn("Q3 Financial Overview", doc_names)
        self.assertIn("Cloud Security Architecture", doc_names)
        self.assertIn("Vendor Mutual NDA", doc_names)
        self.assertNotIn("2026 Headcount Budget", doc_names)  # Bryan's document

    def test_owner_activity_feed_scoped_to_owner_documents(self):
        """Activity feed only shows events touching Alyssa's documents or performed by Alyssa."""
        # Log an activity on Bryan's document
        AuditService.log_document_uploaded(actor=self.owner_2, document=self.doc_hr)

        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        activity_feed = response.context['recent_activity']
        for event in activity_feed:
            # Must either touch an Alyssa document or have Alyssa as actor
            is_alyssa_doc = (event.target_document and event.target_document.owner_id == self.owner_1.pk)
            is_alyssa_actor = (event.actor_id == self.owner_1.pk)
            self.assertTrue(is_alyssa_doc or is_alyssa_actor)

    def test_owner_recent_documents_includes_authorized_actions(self):
        """Owner dashboard includes action links: Detail, Download, Share, Edit, Activity."""
        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, reverse('documents:detail', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertContains(response, reverse('documents:download', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertContains(response, reverse('permissions:manage', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertContains(response, reverse('documents:edit', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertContains(response, reverse('audit:document_activity', kwargs={'doc_id': self.doc_fin.pk}))

    def test_owner_with_zero_documents_displays_zero_metrics(self):
        """A new owner with no documents sees zero counts and empty state."""
        new_owner = User.objects.create_user(
            username='owner_empty',
            email='empty@trustvault.local',
            password=self.password,
            role=User.Role.OWNER
        )
        self.client.login(username='owner_empty', password=self.password)

        response = self.client.get(reverse('dashboard:owner'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['total_documents'], 0)
        self.assertEqual(response.context['shared_count'], 0)
        self.assertEqual(response.context['active_permissions'], 0)
        self.assertContains(response, "No documents uploaded yet")


class ViewerDashboardTests(BaseDashboardTestCase):
    """Validates viewer document scoping, READ vs EDIT distinctions, and action restrictions."""

    def setUp(self):
        super().setUp()
        self.client.login(username='viewer_carla', password=self.password)

    def test_viewer_sees_only_accessible_documents(self):
        """Viewer Carla only sees doc_fin and doc_tech; doc_legal and doc_hr are excluded."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['total_accessible'], 2)

        accessible_names = [d.name for d in context['accessible_documents']]
        self.assertIn("Q3 Financial Overview", accessible_names)
        self.assertIn("Cloud Security Architecture", accessible_names)
        self.assertNotIn("Vendor Mutual NDA", accessible_names)  # Not shared
        self.assertNotIn("2026 Headcount Budget", accessible_names)  # Shared with Dan, not Carla

    def test_viewer_metrics_read_and_edit_counts(self):
        """Viewer Carla has 1 READ document and 1 EDIT document."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)

        context = response.context
        self.assertEqual(context['read_count'], 1)
        self.assertEqual(context['edit_count'], 1)

    def test_viewer_read_permission_displays_read_badge(self):
        """For READ grant, template displays READ badge."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, "READ")
        self.assertContains(response, reverse('documents:download', kwargs={'doc_id': self.doc_fin.pk}))

    def test_viewer_edit_permission_displays_edit_badge_and_edit_action(self):
        """For EDIT grant, template displays EDIT badge and Edit action button."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, "EDIT")
        self.assertContains(response, reverse('documents:edit', kwargs={'doc_id': self.doc_tech.pk}))

    def test_viewer_never_sees_delete_or_share_actions(self):
        """Viewer workspace strictly suppresses Delete and Share actions."""
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)

        # Neither delete nor permissions management links appear for viewer
        self.assertNotContains(response, reverse('documents:delete', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertNotContains(response, reverse('permissions:manage', kwargs={'doc_id': self.doc_fin.pk}))
        self.assertNotContains(response, reverse('documents:delete', kwargs={'doc_id': self.doc_tech.pk}))
        self.assertNotContains(response, reverse('permissions:manage', kwargs={'doc_id': self.doc_tech.pk}))

    def test_viewer_empty_state_when_no_documents_shared(self):
        """A viewer with no shared documents sees clean empty state."""
        new_viewer = User.objects.create_user(
            username='viewer_empty',
            email='viewer_empty@trustvault.local',
            password=self.password,
            role=User.Role.VIEWER
        )
        self.client.login(username='viewer_empty', password=self.password)

        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['total_accessible'], 0)
        self.assertContains(response, "No shared documents available")

    def test_viewer_dashboard_immediate_revocation_consistency(self):
        """When permission is revoked, the document disappears immediately from viewer dashboard."""
        # Prior to revocation, 2 documents accessible
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.context['total_accessible'], 2)

        # Revoke READ on doc_fin
        PermissionService.revoke_permission(
            actor=self.owner_1,
            document=self.doc_fin,
            target_user=self.viewer_1
        )

        # After revocation, only 1 document accessible
        response = self.client.get(reverse('dashboard:viewer'))
        self.assertEqual(response.context['total_accessible'], 1)
        accessible_names = [d.name for d in response.context['accessible_documents']]
        self.assertNotIn("Q3 Financial Overview", accessible_names)
        self.assertIn("Cloud Security Architecture", accessible_names)
