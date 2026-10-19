"""
Management command to seed realistic synthetic demo data into TrustVault.

Security Principles:
  - Generates cryptographically secure, high-entropy passwords dynamically.
  - Allows operator override via environment variables (DEMO_ADMIN_PASSWORD, etc.).
  - Prohibits automated demo creation in production environments (DEBUG=False)
    unless explicitly authorized via ALLOW_DEMO_SEEDING=True.
  - Enforces strict scoping on --clean to never delete non-demo accounts or files.
  - Zero password logging or persistence in audit metadata.
"""

import os
import secrets
import string

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model

from accounts.models import User
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import PermissionType, DocumentPermission
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType, AuditStatus
from audit.services import AuditService


DEMO_USERNAMES = ('admin_demo', 'owner_demo', 'viewer_demo')


def generate_secure_password(length=16):
    """
    Generate a cryptographically secure random password meeting all
    Django AUTH_PASSWORD_VALIDATORS criteria.
    """
    specials = "!@#$%^&*()-_=+"
    alphabet = string.ascii_letters + string.digits + specials
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in password)
                and any(c.islower() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in specials for c in password)):
            return password


class Command(BaseCommand):
    help = "Seeds TrustVault with demo accounts, protected documents, permissions, and audit logs."

    def add_arguments(self, parser):
        parser.add_argument(
            '--clean',
            action='store_true',
            help='Purges existing synthetic demo users and their documents before seeding.',
        )

    def handle(self, *args, **options):
        # 0. Production Safety Gate
        if not settings.DEBUG and os.getenv('ALLOW_DEMO_SEEDING', '').strip().lower() not in ('true', '1', 'yes'):
            raise CommandError(
                "Demo data seeding is prohibited in production (DEBUG=False). "
                "Set ALLOW_DEMO_SEEDING=True if you explicitly intend to seed synthetic data in this environment."
            )

        self.stdout.write(self.style.NOTICE("Initializing TrustVault Demo Data Seeder..."))

        User = get_user_model()
        clean = options.get('clean', False)

        if clean:
            self.stdout.write("Purging prior synthetic demo users and documents...")
            # Safety Constraint: Strictly bound to demo usernames
            demo_docs = Document.objects.filter(owner__username__in=DEMO_USERNAMES)
            for d in demo_docs:
                try:
                    DocumentService.delete_document(actor=d.owner, document_id=d.pk)
                except Exception:
                    d.delete()
            User.objects.filter(username__in=DEMO_USERNAMES).delete()
            self.stdout.write(self.style.SUCCESS("Prior synthetic demo data purged successfully."))

        # 1. Resolve Secure Passwords (Environment Variable Override or Cryptographic Random)
        admin_password = os.getenv('DEMO_ADMIN_PASSWORD') or generate_secure_password()
        owner_password = os.getenv('DEMO_OWNER_PASSWORD') or generate_secure_password()
        viewer_password = os.getenv('DEMO_VIEWER_PASSWORD') or generate_secure_password()

        account_specs = [
            {
                'username': 'admin_demo',
                'email': 'admin@trustvault.local',
                'role': User.Role.ADMIN,
                'password': admin_password,
                'is_staff': True,
                'is_superuser': True,
                'description': 'Administrator (Full platform & audit governance)',
            },
            {
                'username': 'owner_demo',
                'email': 'owner@trustvault.local',
                'role': User.Role.OWNER,
                'password': owner_password,
                'is_staff': False,
                'is_superuser': False,
                'description': 'Document Owner (Upload, grant, edit, revoke)',
            },
            {
                'username': 'viewer_demo',
                'email': 'viewer@trustvault.local',
                'role': User.Role.VIEWER,
                'password': viewer_password,
                'is_staff': False,
                'is_superuser': False,
                'description': 'Viewer (Inspect shared docs, download, edit)',
            },
        ]

        users = {}
        for spec in account_specs:
            user, created = User.objects.get_or_create(
                username=spec['username'],
                defaults={
                    'email': spec['email'],
                    'role': spec['role'],
                    'is_staff': spec['is_staff'],
                    'is_superuser': spec['is_superuser'],
                }
            )
            user.role = spec['role']
            user.is_staff = spec['is_staff']
            user.is_superuser = spec['is_superuser']
            user.set_password(spec['password'])
            user.save()
            users[spec['username']] = user
            action = "Created" if created else "Updated"
            self.stdout.write(f"  [{action}] User: {user.username} ({user.get_role_display()})")

        owner = users['owner_demo']
        viewer = users['viewer_demo']

        # 2. Synthetic Files
        pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\n0000000101 00000 n\n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
        )
        txt_bytes = (
            b"TRUSTVAULT BOARD RESOLUTION - EXECUTIVE DISCLOSURE\n"
            b"Date: 2026-10-19\n"
            b"Status: RESTRICTED CORPORATE RECORD\n"
            b"Summary: Authorized capital expenditure and zero-trust cryptographic key management.\n"
        )

        doc_specs = [
            {
                'name': 'TrustVault Architecture & Threat Model Specification',
                'description': 'Confidential technical specification, STRIDE threat model analysis, and zero-trust verification roadmap.',
                'filename': 'trustvault_spec.pdf',
                'content': pdf_bytes,
                'category': DocumentCategory.TECHNICAL,
                'permission': PermissionType.READ,
            },
            {
                'name': 'Enterprise Security Audit & Penetration Test Report',
                'description': 'Third-party penetration test assessment, OWASP Top 10 compliance audit, and automated vulnerability scanning outputs.',
                'filename': 'security_audit.pdf',
                'content': pdf_bytes,
                'category': DocumentCategory.LEGAL,
                'permission': PermissionType.EDIT,
            },
            {
                'name': 'Board Resolution & Executive Compensation Q3 2026',
                'description': 'Restricted board proceedings, executive remuneration schedules, and confidential governance resolutions.',
                'filename': 'board_resolution.txt',
                'content': txt_bytes,
                'category': DocumentCategory.FINANCIAL,
                'permission': 'REVOKED',
            },
        ]

        created_docs = []
        for dspec in doc_specs:
            # Check if document already exists for owner
            existing = Document.objects.filter(owner=owner, name=dspec['name']).first()
            if existing:
                doc = existing
                self.stdout.write(f"  [Found] Existing document: '{doc.name}' (ID: {doc.pk})")
            else:
                upload_file = SimpleUploadedFile(
                    name=dspec['filename'],
                    content=dspec['content'],
                    content_type='application/pdf' if dspec['filename'].endswith('.pdf') else 'text/plain'
                )
                doc = DocumentService.upload_document(
                    owner=owner,
                    uploaded_file=upload_file,
                    name=dspec['name'],
                    description=dspec['description'],
                    category=dspec['category']
                )
                self.stdout.write(f"  [Created] Document: '{doc.name}' (ID: {doc.pk})")
            created_docs.append((doc, dspec))

        # 3. Provision Permissions and Seed Access Logs
        for doc, dspec in created_docs:
            perm_type = dspec['permission']
            if perm_type == PermissionType.READ:
                PermissionService.grant_permission(
                    actor=owner,
                    document=doc,
                    target_user=viewer,
                    permission_type=PermissionType.READ
                )
                # Seed authorized download activity
                AuditService.log_document_downloaded(actor=viewer, document=doc)
                self.stdout.write(f"  [Permission] Granted READ on '{doc.name}' to {viewer.username}")

            elif perm_type == PermissionType.EDIT:
                PermissionService.grant_permission(
                    actor=owner,
                    document=doc,
                    target_user=viewer,
                    permission_type=PermissionType.EDIT
                )
                # Seed authorized download activity
                AuditService.log_document_downloaded(actor=viewer, document=doc)
                self.stdout.write(f"  [Permission] Granted EDIT on '{doc.name}' to {viewer.username}")

            elif perm_type == 'REVOKED':
                # First grant then revoke
                PermissionService.grant_permission(
                    actor=owner,
                    document=doc,
                    target_user=viewer,
                    permission_type=PermissionType.READ
                )
                PermissionService.revoke_permission(
                    actor=owner,
                    document=doc,
                    target_user=viewer
                )
                # Seed an unauthorized access denial log
                AuditService.log_event(
                    event_type=AuditEventType.SECURITY_ACCESS_DENIED,
                    actor=viewer,
                    target_document=doc,
                    status=AuditStatus.FAILURE,
                    metadata={
                        'reason': 'Access denied: User lacks active authorization on document',
                        'target_document_id': doc.pk,
                        'path': f'/documents/{doc.pk}/download/'
                    }
                )
                self.stdout.write(f"  [Permission] Revoked access on '{doc.name}' from {viewer.username} (Access Denied logged)")

        # 4. Display Credentials Exclusively to Authorized Console Operator
        self.stdout.write(self.style.SUCCESS("\nTrustVault Demo Data successfully provisioned!"))
        self.stdout.write("\n" + "=" * 74)
        self.stdout.write(self.style.WARNING("ATTENTION: DEMO CREDENTIALS GENERATED DYNAMICALLY"))
        self.stdout.write("These credentials are provisioned for local development and evaluation.")
        self.stdout.write("Passwords are never committed to version control or saved in audit logs.")
        self.stdout.write("=" * 74)
        for idx, spec in enumerate(account_specs, start=1):
            self.stdout.write(f"  {idx}. {spec['description']}:")
            self.stdout.write(f"     Username: {spec['username']}")
            self.stdout.write(f"     Password: {spec['password']}")
            self.stdout.write(f"     Role:     {spec['role']}")
        self.stdout.write("=" * 74 + "\n")
