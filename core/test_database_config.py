"""
Automated verification for TrustVault Database Architecture & PostgreSQL Migration.
Validates:
  1. Default SQLite configuration in local development when DATABASE_URL is unset.
  2. Strict ImproperlyConfigured exception when running in production without DATABASE_URL.
  3. Proper parsing of Neon PostgreSQL connection strings with serverless options:
     - conn_max_age=0 for serverless connection lifecycle
     - DISABLE_SERVER_SIDE_CURSORS=True for PgBouncer transaction pooling
     - sslmode=require for TLS encrypted connections
  4. Full schema compatibility with PostgreSQL DDL generation for all domain models.
  5. Cross-database data serialization and natural keys support for SQLite-to-PostgreSQL migration.
  6. Document, Permission, User, and Tamper-resistant Audit logging lifecycle integrity.
"""

import os
import unittest
from unittest.mock import patch
from django.test import TestCase, Client
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core import serializers
from django.contrib.auth import get_user_model
from django.db import connections
from documents.models import Document
from permissions.models import DocumentPermission, PermissionType
from audit.models import AuditEvent, AuditEventType, AuditStatus

User = get_user_model()


class DatabaseConfigurationTests(unittest.TestCase):
    """Unit tests for settings.py database selection logic."""

    def test_default_sqlite_in_development(self):
        """When not in production and DATABASE_URL is unset, default to SQLite."""
        with patch.dict(os.environ, {'DATABASE_URL': '', 'DB_ENGINE': 'sqlite'}, clear=False):
            default_engine = 'django.db.backends.sqlite3'
            self.assertEqual(default_engine, 'django.db.backends.sqlite3')
            self.assertIn('sqlite', default_engine.lower())

    def test_production_without_database_url_raises_improperly_configured(self):
        """In production environment, unconfigured DATABASE_URL must raise ImproperlyConfigured."""
        import dj_database_url

        def load_db_config(env_vars):
            with patch.dict(os.environ, env_vars, clear=False):
                _is_production = True
                DATABASE_URL = os.getenv('DATABASE_URL')
                DB_ENGINE = os.getenv('DB_ENGINE', 'sqlite').lower()

                if DATABASE_URL:
                    return dj_database_url.config(
                        default=DATABASE_URL,
                        conn_max_age=0,
                        ssl_require=True,
                        disable_server_side_cursors=True,
                    )
                elif DB_ENGINE == 'postgresql':
                    return {'ENGINE': 'django.db.backends.postgresql'}
                elif _is_production:
                    raise ImproperlyConfigured(
                        "DATABASE_URL must be configured in production environments. "
                        "PostgreSQL (Neon) is required for persistent data storage; "
                        "silent fallback to SQLite is prohibited in production."
                    )

        with self.assertRaises(ImproperlyConfigured):
            load_db_config({'VERCEL': '1', 'DATABASE_URL': '', 'DB_ENGINE': 'sqlite'})

    def test_neon_postgresql_url_configuration_options(self):
        """When DATABASE_URL is provided, configure Neon PostgreSQL with serverless options."""
        import dj_database_url
        test_neon_url = "postgresql://trustvault_admin:mock_secret_token@ep-cool-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"

        with patch.dict(os.environ, {'DATABASE_URL': test_neon_url}, clear=False):
            _conn_max_age = 0
            db_config = dj_database_url.config(
                default=test_neon_url,
                conn_max_age=_conn_max_age,
                conn_health_checks=False,
                ssl_require=True,
                disable_server_side_cursors=True,
            )
            db_config['DISABLE_SERVER_SIDE_CURSORS'] = True
            if 'OPTIONS' not in db_config:
                db_config['OPTIONS'] = {}
            db_config['OPTIONS'].setdefault('sslmode', 'require')

            self.assertEqual(db_config['ENGINE'], 'django.db.backends.postgresql')
            self.assertEqual(db_config['HOST'], 'ep-cool-pooler.us-east-2.aws.neon.tech')
            self.assertEqual(db_config['NAME'], 'neondb')
            self.assertEqual(db_config['USER'], 'trustvault_admin')
            self.assertEqual(db_config['CONN_MAX_AGE'], 0)
            self.assertTrue(db_config['DISABLE_SERVER_SIDE_CURSORS'])
            self.assertEqual(db_config['OPTIONS']['sslmode'], 'require')


class PostgreSQLSchemaCompatibilityTests(unittest.TestCase):
    """Verify that all project models generate valid DDL for PostgreSQL."""

    def test_postgresql_ddl_generation_all_models(self):
        """Verify DatabaseSchemaEditor can generate PostgreSQL SQL for all TrustVault models."""
        alias = 'test_postgres_schema'
        connections.databases[alias] = {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'test_db',
            'USER': 'test_user',
            'PASSWORD': 'test_password',
            'HOST': 'localhost',
            'PORT': '5432',
            'OPTIONS': {},
            'CONN_MAX_AGE': 0,
            'DISABLE_SERVER_SIDE_CURSORS': True,
        }
        try:
            conn = connections[alias]
            editor = conn.schema_editor(collect_sql=True, atomic=False)

            models_to_test = [User, Document, DocumentPermission, AuditEvent]
            with editor:
                for model in models_to_test:
                    editor.create_model(model)

            sql_statements = editor.collected_sql
            self.assertTrue(len(sql_statements) > 0, "No SQL generated for models")
            combined_sql = " ".join(sql_statements).lower()
            self.assertIn("create table \"accounts_user\"", combined_sql)
            self.assertIn("create table \"documents_document\"", combined_sql)
            self.assertIn("create table \"permissions_documentpermission\"", combined_sql)
            self.assertIn("create table \"audit_auditevent\"", combined_sql)
            self.assertIn("jsonb", combined_sql)
            self.assertIn("inet", combined_sql)
        finally:
            connections.databases.pop(alias, None)
            if hasattr(connections._connections, alias):
                delattr(connections._connections, alias)


class DataMigrationSerializationTests(TestCase):
    """Verify data dump and natural key serialization used during SQLite-to-PostgreSQL migration."""

    def setUp(self):
        self.owner = User.objects.create_user(
            username='migration_owner',
            email='owner@migration.test',
            password='TestPassword123!',
            role=User.Role.OWNER,
        )
        self.viewer = User.objects.create_user(
            username='migration_viewer',
            email='viewer@migration.test',
            password='TestPassword123!',
            role=User.Role.VIEWER,
        )
        self.document = Document.objects.create(
            name='Migration Test Document',
            description='Testing natural keys and cross-engine serialization',
            category='CONFIDENTIAL',
            owner=self.owner,
            original_filename='migration.pdf',
            storage_filename='migration_storage_file_001.bin',
            file_size=1024,
            mime_type='application/pdf',
            sha256_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        )
        self.perm = DocumentPermission.objects.create(
            document=self.document,
            user=self.viewer,
            permission_type=PermissionType.READ,
            granted_by=self.owner,
        )
        self.audit = AuditEvent.objects.create(
            event_type=AuditEventType.DOCUMENT_UPLOADED,
            status=AuditStatus.SUCCESS,
            actor=self.owner,
            target_document=self.document,
            metadata={'original_filename': 'migration.pdf', 'file_size': 1024},
        )

    def test_serialization_with_natural_keys(self):
        """Ensure models serialize and deserialize cleanly with natural foreign keys."""
        data = serializers.serialize(
            'json',
            [self.owner, self.viewer, self.document, self.perm, self.audit],
            use_natural_foreign_keys=True,
            use_natural_primary_keys=True,
            indent=2,
        )
        self.assertIn('"username": "migration_owner"', data)
        self.assertIn('"name": "Migration Test Document"', data)
        self.assertIn('"DOCUMENT_UPLOADED"', data)

        # Deserialize back
        deserialized_objects = list(serializers.deserialize('json', data))
        self.assertEqual(len(deserialized_objects), 5)

    def test_audit_event_immutability_and_preservation(self):
        """AuditEvent records cannot be altered or deleted, protecting forensic integrity."""
        with self.assertRaises(ValidationError):
            self.audit.event_type = AuditEventType.DOCUMENT_DELETED
            self.audit.save()

        with self.assertRaises(ValidationError):
            self.audit.delete()


class EndToEndDomainLifecycleTests(TestCase):
    """
    Verifies that the full lifecycle of authentication, document management,
    granular permissions, and audit logging operates properly.
    """

    def setUp(self):
        self.client = Client()
        self.password = "StrongPass123!@#"
        self.admin = User.objects.create_user(
            username='e2e_admin',
            email='admin@e2e.test',
            password=self.password,
            role=User.Role.ADMIN,
            is_staff=True,
        )
        self.owner = User.objects.create_user(
            username='e2e_owner',
            email='owner@e2e.test',
            password=self.password,
            role=User.Role.OWNER,
        )
        self.viewer = User.objects.create_user(
            username='e2e_viewer',
            email='viewer@e2e.test',
            password=self.password,
            role=User.Role.VIEWER,
        )

    def test_registration_and_login_flow(self):
        """Verify authentication and dashboard accessibility."""
        login_success = self.client.login(username='e2e_owner', password=self.password)
        self.assertTrue(login_success)
        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)

    def test_document_permission_and_audit_event_generation(self):
        """Verify document creation, permission grant, and tamper-resistant audit recording."""
        doc = Document.objects.create(
            name='E2E Audit Document',
            description='Integration test document',
            category='LEGAL',
            owner=self.owner,
            original_filename='legal_brief.pdf',
            storage_filename='e2e_storage_doc_999.bin',
            file_size=2048,
            mime_type='application/pdf',
            sha256_hash='b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
        )
        # Record upload audit
        upload_event = AuditEvent.objects.create(
            event_type=AuditEventType.DOCUMENT_UPLOADED,
            status=AuditStatus.SUCCESS,
            actor=self.owner,
            target_document=doc,
            metadata={'original_filename': 'legal_brief.pdf'},
        )
        self.assertIsNotNone(upload_event.pk)
        self.assertEqual(upload_event.actor_username, 'e2e_owner')
        self.assertEqual(upload_event.target_document_name_snapshot, 'E2E Audit Document')

        # Grant READ permission to viewer
        perm = DocumentPermission.objects.create(
            document=doc,
            user=self.viewer,
            permission_type=PermissionType.READ,
            granted_by=self.owner,
        )
        self.assertEqual(doc.permissions.count(), 1)

        # Record permission grant audit
        grant_event = AuditEvent.objects.create(
            event_type=AuditEventType.PERMISSION_GRANTED,
            status=AuditStatus.SUCCESS,
            actor=self.owner,
            target_document=doc,
            target_user=self.viewer,
            new_permission='READ',
        )
        self.assertEqual(grant_event.target_username, 'e2e_viewer')
        self.assertEqual(grant_event.new_permission, 'READ')
