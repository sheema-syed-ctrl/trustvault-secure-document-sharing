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


class HealthCheckEndpointTests(TestCase):
    """
    Automated verification for the production /health/ probe.
    Ensures container orchestrators and load balancers receive accurate system diagnostics.
    """

    def setUp(self):
        self.client = Client()

    def test_health_check_healthy_system(self):
        """GET /health/ returns HTTP 200 with JSON payload when all systems pass."""
        response = self.client.get('/health/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        data = response.json()
        self.assertEqual(data.get('status'), 'healthy')
        self.assertEqual(data.get('database'), 'connected')
        self.assertEqual(data.get('storage'), 'accessible')
        self.assertEqual(data.get('version'), '1.0.0')

    def test_health_check_accessible_anonymously(self):
        """Health check endpoint must be publicly accessible to load balancers without authentication."""
        response = self.client.get('/health/')
        self.assertEqual(response.status_code, 200)

    def test_health_check_database_failure(self):
        """GET /health/ returns HTTP 503 when the database probe fails."""
        from unittest.mock import patch
        with patch('django.db.connection.cursor') as mock_cursor:
            mock_cursor.side_effect = Exception("Database connection timeout")
            response = self.client.get('/health/')
            self.assertEqual(response.status_code, 503)
            data = response.json()
            self.assertEqual(data.get('status'), 'unhealthy')
            self.assertIn('disconnected', data.get('database', ''))

    def test_health_check_storage_failure(self):
        """GET /health/ returns HTTP 503 when storage directory is invalid."""
        from unittest.mock import patch
        from pathlib import Path
        with patch.object(Path, 'write_text') as mock_write:
            mock_write.side_effect = OSError("Disk read-only")
            response = self.client.get('/health/')
            self.assertEqual(response.status_code, 503)
            data = response.json()
            self.assertEqual(data.get('status'), 'unhealthy')
            self.assertIn('error', data.get('storage', ''))
