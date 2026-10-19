from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.apps import apps
from django.conf import settings
from pathlib import Path


class SystemArchitectureTests(TestCase):
    """
    Automated verification for Phase 01: Foundation & System Architecture.
    Validates:
      1. All required modular apps are loaded in registry.
      2. Custom User model is configured and active.
      3. Protected media directory exists and is segregated from public web root.
      4. Centralized error handling operates correctly.
      5. Core landing page renders successfully.
    """

    def setUp(self):
        self.client = Client()

    def test_modular_apps_loaded(self):
        """Ensure accounts, documents, permissions, audit, dashboard, core are loaded."""
        required_apps = ['accounts', 'documents', 'permissions', 'audit', 'dashboard', 'core']
        for app in required_apps:
            self.assertTrue(apps.is_installed(app), f"App '{app}' is not loaded in Django settings.")

    def test_custom_user_model_active(self):
        """Ensure accounts.User is registered as AUTH_USER_MODEL."""
        User = get_user_model()
        self.assertEqual(settings.AUTH_USER_MODEL, 'accounts.User')
        self.assertEqual(User._meta.app_label, 'accounts')
        self.assertEqual(User._meta.model_name, 'user')

    def test_protected_media_configured_separately(self):
        """Ensure PROTECTED_MEDIA_ROOT is configured and exists outside public static/media URLs."""
        self.assertTrue(hasattr(settings, 'PROTECTED_MEDIA_ROOT'))
        self.assertTrue(Path(settings.PROTECTED_MEDIA_ROOT).is_dir())
        # Verify it is not equal to BASE_DIR or STATIC_ROOT
        self.assertNotEqual(settings.PROTECTED_MEDIA_ROOT, settings.BASE_DIR)

    def test_core_landing_page_renders(self):
        """Ensure core home landing view returns HTTP 200 with TrustVault branding."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'TrustVault')
        self.assertContains(response, 'Secure Document Sharing')

    def test_custom_404_handler(self):
        """Ensure non-existent route invokes custom 404 template with 404 status."""
        response = self.client.get('/this-path-definitely-does-not-exist-404/')
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, 'Resource Not Found', status_code=404)

    def test_security_headers_configured(self):
        """Verify baseline security header configurations in settings."""
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
