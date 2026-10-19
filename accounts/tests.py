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
