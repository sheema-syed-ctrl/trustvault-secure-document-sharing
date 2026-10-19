"""
Comprehensive automated test suite for Phase 02: Authentication & Role-Based Access Control.
Tests identity lifecycle, session handling, RBAC enforcement, privilege escalation defenses,
self-role protection, and CSRF compliance.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from accounts.services import RBACService
from accounts.forms import UserRegistrationForm, AdminUserUpdateForm

User = get_user_model()


class AuthenticationAndRBACTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.password = "StrongPass123!@#"

        # Test user accounts
        self.admin_user = User.objects.create_user(
            username='admin_alice',
            email='alice@trustvault.local',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True
        )

        self.owner_user = User.objects.create_user(
            username='owner_bob',
            email='bob@trustvault.local',
            password=self.password,
            role=User.Role.OWNER
        )

        self.viewer_user = User.objects.create_user(
            username='viewer_charlie',
            email='charlie@trustvault.local',
            password=self.password,
            role=User.Role.VIEWER
        )

    # -------------------------------------------------------------------------
    # 1. Custom User Model & RBAC Helper Methods
    # -------------------------------------------------------------------------
    def test_user_model_role_properties(self):
        """Verify role properties reflect user role accurately."""
        self.assertTrue(self.admin_user.is_admin_role)
        self.assertFalse(self.admin_user.is_owner_role)
        self.assertFalse(self.admin_user.is_viewer_role)

        self.assertTrue(self.owner_user.is_owner_role)
        self.assertFalse(self.owner_user.is_admin_role)

        self.assertTrue(self.viewer_user.is_viewer_role)
        self.assertFalse(self.viewer_user.is_admin_role)

    def test_rbac_service_methods(self):
        """Verify RBACService helper evaluations."""
        self.assertTrue(RBACService.is_admin(self.admin_user))
        self.assertFalse(RBACService.is_admin(self.owner_user))
        self.assertFalse(RBACService.is_admin(self.viewer_user))
        self.assertFalse(RBACService.is_admin(None))

        self.assertTrue(RBACService.can_manage_users(self.admin_user))
        self.assertFalse(RBACService.can_manage_users(self.owner_user))
        self.assertFalse(RBACService.can_manage_users(self.viewer_user))

        self.assertTrue(RBACService.can_upload_documents(self.owner_user))
        self.assertFalse(RBACService.can_upload_documents(self.viewer_user))
        self.assertFalse(RBACService.can_upload_documents(self.admin_user))

    # -------------------------------------------------------------------------
    # 2. Registration & Privilege Escalation Defenses
    # -------------------------------------------------------------------------
    def test_valid_owner_registration(self):
        """Verify successful registration with OWNER role."""
        response = self.client.post(reverse('accounts:register'), {
            'username': 'new_owner',
            'email': 'new_owner@example.com',
            'role': User.Role.OWNER,
            'password1': self.password,
            'password2': self.password,
        })
        self.assertRedirects(response, reverse('accounts:login'))
        user = User.objects.get(username='new_owner')
        self.assertEqual(user.role, User.Role.OWNER)

    def test_valid_viewer_registration(self):
        """Verify successful registration with VIEWER role."""
        response = self.client.post(reverse('accounts:register'), {
            'username': 'new_viewer',
            'email': 'new_viewer@example.com',
            'role': User.Role.VIEWER,
            'password1': self.password,
            'password2': self.password,
        })
        self.assertRedirects(response, reverse('accounts:login'))
        user = User.objects.get(username='new_viewer')
        self.assertEqual(user.role, User.Role.VIEWER)

    def test_privilege_escalation_registration_blocked(self):
        """
        SECURITY TEST:
        Submitting role=ADMIN in registration form MUST be rejected by server-side validation.
        """
        response = self.client.post(reverse('accounts:register'), {
            'username': 'attacker_admin',
            'email': 'attacker@example.com',
            'role': 'ADMIN',
            'password1': self.password,
            'password2': self.password,
        })
        # Must not redirect to login, must return form with validation error
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='attacker_admin').exists())
        self.assertFormError(
            response.context['form'], 'role',
            'Select a valid choice. ADMIN is not one of the available choices.'
        )

    # -------------------------------------------------------------------------
    # 3. Authentication: Login & Logout
    # -------------------------------------------------------------------------
    def test_successful_login(self):
        """Verify login with correct credentials sets session and redirects to dashboard."""
        response = self.client.post(reverse('accounts:login'), {
            'username': 'admin_alice',
            'password': self.password,
        })
        self.assertRedirects(response, reverse('dashboard:index'))
        self.assertIn('_auth_user_id', self.client.session)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.admin_user.pk)

    def test_failed_login(self):
        """Verify failed login with incorrect password does not establish session."""
        response = self.client.post(reverse('accounts:login'), {
            'username': 'admin_alice',
            'password': 'WrongPassword123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertContains(response, 'Invalid username or password')

    def test_open_redirect_prevention_on_login(self):
        """
        SECURITY TEST:
        Attempting login with malicious external 'next' URL must be sanitized to default dashboard.
        """
        response = self.client.post(reverse('accounts:login') + '?next=https://malicious-site.com/steal-creds', {
            'username': 'admin_alice',
            'password': self.password,
        })
        # Must redirect safely to internal dashboard, NOT external site
        self.assertRedirects(response, reverse('dashboard:index'))

    def test_secure_logout_post_only(self):
        """Verify logout flushes session when submitted via POST."""
        self.client.login(username='admin_alice', password=self.password)
        self.assertIn('_auth_user_id', self.client.session)

        response = self.client.post(reverse('accounts:logout'))
        self.assertRedirects(response, reverse('accounts:login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_get_method_rejected(self):
        """
        SECURITY TEST:
        GET request to logout must return HTTP 405 Method Not Allowed to prevent CSRF logout.
        """
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.get(reverse('accounts:logout'))
        self.assertEqual(response.status_code, 405)
        # Session remains active
        self.assertIn('_auth_user_id', self.client.session)

    # -------------------------------------------------------------------------
    # 4. Anonymous Access & Role Restrictions
    # -------------------------------------------------------------------------
    def test_anonymous_access_dashboard_redirects_to_login(self):
        """Anonymous access to /dashboard/ must redirect to login."""
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('accounts:login')))

    def test_anonymous_access_user_list_redirects_to_login(self):
        """Anonymous access to administrative user list redirects to login."""
        response = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('accounts:login')))

    def test_non_admin_access_user_list_forbidden(self):
        """
        SECURITY TEST (RBAC):
        Document Owner or Viewer attempting to access user directory must be denied (HTTP 403).
        """
        # Test Owner
        self.client.login(username='owner_bob', password=self.password)
        response = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(response.status_code, 403)

        # Test Viewer
        self.client.login(username='viewer_charlie', password=self.password)
        response = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(response.status_code, 403)

    def test_admin_access_user_list_permitted(self):
        """Administrator can access user directory."""
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'User Directory')
        self.assertContains(response, 'admin_alice')
        self.assertContains(response, 'owner_bob')
        self.assertContains(response, 'viewer_charlie')

    # -------------------------------------------------------------------------
    # 5. Administrative User Provisioning & Role Modification
    # -------------------------------------------------------------------------
    def test_admin_can_provision_any_role(self):
        """Administrator can provision an account with any role."""
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.post(reverse('accounts:user_create'), {
            'username': 'new_admin_david',
            'email': 'david@trustvault.local',
            'first_name': 'David',
            'last_name': 'Admin',
            'role': User.Role.ADMIN,
            'password1': self.password,
            'password2': self.password,
            'is_active': True,
        })
        self.assertRedirects(response, reverse('accounts:user_list'))
        created = User.objects.get(username='new_admin_david')
        self.assertEqual(created.role, User.Role.ADMIN)

    def test_non_admin_cannot_provision_user(self):
        """Non-admin cannot access user provisioning endpoint."""
        self.client.login(username='owner_bob', password=self.password)
        response = self.client.post(reverse('accounts:user_create'), {
            'username': 'sneaky_user',
            'email': 'sneaky@example.com',
            'role': User.Role.ADMIN,
            'password1': self.password,
            'password2': self.password,
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(username='sneaky_user').exists())

    def test_admin_can_change_other_user_role(self):
        """Administrator can elevate or modify another user's role."""
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.post(reverse('accounts:user_edit', args=[self.viewer_user.id]), {
            'role': User.Role.OWNER,
            'email': self.viewer_user.email,
            'is_active': True,
        })
        self.assertRedirects(response, reverse('accounts:user_list'))
        self.viewer_user.refresh_from_db()
        self.assertEqual(self.viewer_user.role, User.Role.OWNER)

    def test_admin_cannot_demote_themselves(self):
        """
        SECURITY TEST:
        Administrator cannot demote themselves to prevent accidental or malicious lockouts.
        """
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.post(reverse('accounts:user_edit', args=[self.admin_user.id]), {
            'role': User.Role.VIEWER,
            'email': self.admin_user.email,
            'is_active': True,
        })
        self.assertEqual(response.status_code, 200)
        self.admin_user.refresh_from_db()
        self.assertEqual(self.admin_user.role, User.Role.ADMIN)
        self.assertContains(response, 'Self-demotion prevented')

    def test_admin_cannot_deactivate_themselves(self):
        """
        SECURITY TEST:
        Administrator cannot deactivate their own account.
        """
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.post(reverse('accounts:user_edit', args=[self.admin_user.id]), {
            'role': User.Role.ADMIN,
            'email': self.admin_user.email,
            'is_active': False,
        })
        self.assertEqual(response.status_code, 200)
        self.admin_user.refresh_from_db()
        self.assertTrue(self.admin_user.is_active)
        self.assertContains(response, 'Self-deactivation prevented')

    # -------------------------------------------------------------------------
    # 6. Role-Specific Dashboard Routing
    # -------------------------------------------------------------------------
    def test_admin_dashboard_routing(self):
        """Admin user accessing /dashboard/ renders Admin Control Panel."""
        self.client.login(username='admin_alice', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Administrator Control Panel')
        self.assertContains(response, 'Trust Boundary Notice')

    def test_owner_dashboard_routing(self):
        """Owner accessing /dashboard/ renders Owner Workspace."""
        self.client.login(username='owner_bob', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Document Owner Dashboard')
        self.assertContains(response, 'My Uploaded Documents')

    def test_viewer_dashboard_routing(self):
        """Viewer accessing /dashboard/ renders Viewer Workspace."""
        self.client.login(username='viewer_charlie', password=self.password)
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Viewer Workspace')
        self.assertContains(response, 'Documents Shared With Me')

    # -------------------------------------------------------------------------
    # 7. CSRF Protection Behavior
    # -------------------------------------------------------------------------
    def test_csrf_token_present_in_forms(self):
        """Verify CSRF input tokens are rendered in login and registration forms."""
        login_res = self.client.get(reverse('accounts:login'))
        self.assertContains(login_res, 'csrfmiddlewaretoken')

        register_res = self.client.get(reverse('accounts:register'))
        self.assertContains(register_res, 'csrfmiddlewaretoken')

    def test_csrf_enforced_on_state_changes(self):
        """
        SECURITY TEST:
        Client enforcing CSRF must reject POST submissions without valid CSRF token.
        """
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(reverse('accounts:login'), {
            'username': 'admin_alice',
            'password': self.password,
        })
        # Must be rejected with 403 Forbidden due to missing CSRF token
        self.assertEqual(response.status_code, 403)


from django.test import override_settings


@override_settings(DEBUG=True)
class SeedDemoDataCommandTests(TestCase):
    """Automated verification for the seed_demo_data management command."""

    def test_seed_demo_data_execution_and_idempotency(self):
        """Verify command provisions all demo entities, generates dynamic passwords, and runs idempotently."""
        from io import StringIO
        from django.core.management import call_command
        from documents.models import Document
        from permissions.models import DocumentPermission, PermissionType

        out = StringIO()
        call_command('seed_demo_data', stdout=out)
        output = out.getvalue()

        self.assertIn('admin_demo', output)
        self.assertIn('owner_demo', output)
        self.assertIn('viewer_demo', output)
        self.assertIn('ATTENTION: DEMO CREDENTIALS GENERATED DYNAMICALLY', output)

        # Confirm hardcoded predictable passwords are NEVER rendered
        self.assertNotIn('AdminPassword123!', output)
        self.assertNotIn('OwnerPassword123!', output)
        self.assertNotIn('ViewerPassword123!', output)

        # Verify users exist with correct roles
        admin_u = User.objects.get(username='admin_demo')
        owner_u = User.objects.get(username='owner_demo')
        viewer_u = User.objects.get(username='viewer_demo')

        self.assertEqual(admin_u.role, User.Role.ADMIN)
        self.assertEqual(owner_u.role, User.Role.OWNER)
        self.assertEqual(viewer_u.role, User.Role.VIEWER)

        # Verify documents exist
        docs = Document.objects.filter(owner=owner_u)
        self.assertEqual(docs.count(), 3)

        # Verify permissions
        doc1 = docs.get(name='TrustVault Architecture & Threat Model Specification')
        doc2 = docs.get(name='Enterprise Security Audit & Penetration Test Report')
        doc3 = docs.get(name='Board Resolution & Executive Compensation Q3 2026')

        self.assertTrue(DocumentPermission.objects.filter(document=doc1, user=viewer_u, permission_type=PermissionType.READ).exists())
        self.assertTrue(DocumentPermission.objects.filter(document=doc2, user=viewer_u, permission_type=PermissionType.EDIT).exists())
        # doc3 permission should be revoked
        self.assertFalse(DocumentPermission.objects.filter(document=doc3, user=viewer_u).exists())

        # Test idempotency (run again without error)
        out2 = StringIO()
        call_command('seed_demo_data', stdout=out2)
        output2 = out2.getvalue()
        self.assertIn('TrustVault Demo Data successfully provisioned!', output2)

    def test_seed_demo_data_env_var_override_and_authentication(self):
        """Verify environment variable password overrides work and authenticate successfully."""
        import os
        from unittest.mock import patch
        from io import StringIO
        from django.core.management import call_command
        from django.contrib.auth import authenticate

        env_overrides = {
            'DEMO_ADMIN_PASSWORD': 'CustomAdminSecret99!@#',
            'DEMO_OWNER_PASSWORD': 'CustomOwnerSecret99!@#',
            'DEMO_VIEWER_PASSWORD': 'CustomViewerSecret99!@#',
        }

        with patch.dict(os.environ, env_overrides):
            out = StringIO()
            call_command('seed_demo_data', stdout=out)
            output = out.getvalue()

            self.assertIn('CustomAdminSecret99!@#', output)
            self.assertIn('CustomOwnerSecret99!@#', output)
            self.assertIn('CustomViewerSecret99!@#', output)

            # Test real authentication using provisioned credentials
            admin_auth = authenticate(username='admin_demo', password='CustomAdminSecret99!@#')
            self.assertIsNotNone(admin_auth)
            self.assertEqual(admin_auth.username, 'admin_demo')

            owner_auth = authenticate(username='owner_demo', password='CustomOwnerSecret99!@#')
            self.assertIsNotNone(owner_auth)
            self.assertEqual(owner_auth.username, 'owner_demo')

            viewer_auth = authenticate(username='viewer_demo', password='CustomViewerSecret99!@#')
            self.assertIsNotNone(viewer_auth)
            self.assertEqual(viewer_auth.username, 'viewer_demo')

    def test_seed_demo_data_production_safety_gate(self):
        """Verify demo seeder refuses execution when DEBUG=False without explicit authorization."""
        import os
        from unittest.mock import patch
        from io import StringIO
        from django.test import override_settings
        from django.core.management import call_command
        from django.core.management.base import CommandError

        # In production without ALLOW_DEMO_SEEDING: must raise CommandError
        with override_settings(DEBUG=False):
            with patch.dict(os.environ, {'ALLOW_DEMO_SEEDING': ''}):
                with self.assertRaises(CommandError) as cm:
                    call_command('seed_demo_data', stdout=StringIO())
                self.assertIn("Demo data seeding is prohibited in production", str(cm.exception))

            # In production WITH ALLOW_DEMO_SEEDING=True: must succeed
            with patch.dict(os.environ, {'ALLOW_DEMO_SEEDING': 'True'}):
                out = StringIO()
                call_command('seed_demo_data', stdout=out)
                self.assertIn('TrustVault Demo Data successfully provisioned!', out.getvalue())

    def test_seed_demo_data_clean_preserves_non_demo_users_and_documents(self):
        """Verify --clean only purges synthetic demo users and leaves other data intact."""
        from io import StringIO
        from django.core.management import call_command
        from django.core.files.uploadedfile import SimpleUploadedFile
        from documents.models import Document, DocumentCategory
        from documents.services import DocumentService

        # Create real/independent production user and document
        regular_owner = User.objects.create_user(
            username='legitimate_owner',
            email='legit@corp.example.com',
            password='ComplexPassword123!@#',
            role=User.Role.OWNER
        )
        sample_file = SimpleUploadedFile(
            name='critical_report.txt',
            content=b'CLASSIFIED ENTERPRISE ASSET',
            content_type='text/plain'
        )
        legit_doc = DocumentService.upload_document(
            owner=regular_owner,
            uploaded_file=sample_file,
            name='Critical Enterprise Asset',
            description='Must never be purged by demo cleanup',
            category=DocumentCategory.FINANCIAL
        )

        # Execute demo seeding with --clean
        out = StringIO()
        call_command('seed_demo_data', clean=True, stdout=out)

        # Verify legitimate user and their document are completely preserved
        self.assertTrue(User.objects.filter(username='legitimate_owner').exists())
        self.assertTrue(Document.objects.filter(pk=legit_doc.pk, name='Critical Enterprise Asset').exists())

        # Verify demo entities exist
        self.assertTrue(User.objects.filter(username='admin_demo').exists())
        self.assertTrue(User.objects.filter(username='owner_demo').exists())
        self.assertTrue(User.objects.filter(username='viewer_demo').exists())
