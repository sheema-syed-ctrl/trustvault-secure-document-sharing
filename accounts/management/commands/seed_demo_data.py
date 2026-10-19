"""
Management command to seed realistic synthetic demo data into TrustVault.
Creates:
  - 3 Role-specific users: admin_demo, owner_demo, viewer_demo
  - 3 Synthetic documents in protected private storage
  - Granular permissions: READ, EDIT, and Revoked access
  - Comprehensive persistent audit trail entries
"""

from django.core.management.base import BaseCommand
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.db import transaction

from accounts.models import User
from documents.models import Document, DocumentCategory
from documents.services import DocumentService
from permissions.models import PermissionType, DocumentPermission
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType, AuditStatus
from audit.services import AuditService


class Command(BaseCommand):
    help = "Seeds TrustVault with demo accounts, protected documents, permissions, and audit logs."

    def add_arguments(self, parser):
        parser.add_argument(
            '--clean',
            action='store_true',
            help='Purges existing demo users and associated documents before seeding.',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Initializing TrustVault Demo Data Seeder..."))

        User = get_user_model()
        clean = options.get('clean', False)

        demo_usernames = ['admin_demo', 'owner_demo', 'viewer_demo']

        if clean:
            self.stdout.write("Purging prior demo users and data...")
            docs = Document.objects.filter(owner__username__in=demo_usernames)
            for d in docs:
                try:
                    DocumentService.delete_document(actor=d.owner, document_id=d.pk)
                except Exception:
                    d.delete()
            User.objects.filter(username__in=demo_usernames).delete()
            self.stdout.write(self.style.SUCCESS("Prior demo data purged successfully."))

        # 1. Create or retrieve demo accounts
        users = {}
        account_specs = [
            {
                'username': 'admin_demo',
                'email': 'admin@trustvault.local',
                'role': User.Role.ADMIN,
                'password': 'AdminPassword123!',
                'is_staff': True,
                'is_superuser': True,
            },
            {
                'username': 'owner_demo',
                'email': 'owner@trustvault.local',
                'role': User.Role.OWNER,
                'password': 'OwnerPassword123!',
                'is_staff': False,
                'is_superuser': False,
            },
            {
                'username': 'viewer_demo',
                'email': 'viewer@trustvault.local',
                'role': User.Role.VIEWER,
                'password': 'ViewerPassword123!',
                'is_staff': False,
                'is_superuser': False,
            },
        ]

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

        self.stdout.write(self.style.SUCCESS("\nTrustVault Demo Data successfully provisioned!"))
        self.stdout.write("\n" + "=" * 70)
        self.stdout.write("DEMO ACCOUNTS REFERENCE:")
        self.stdout.write("=" * 70)
        self.stdout.write("  1. Administrator:")
        self.stdout.write("     Username: admin_demo")
        self.stdout.write("     Password: AdminPassword123!")
        self.stdout.write("     Role:     Administrator (Full platform & audit governance)")
        self.stdout.write("  2. Document Owner:")
        self.stdout.write("     Username: owner_demo")
        self.stdout.write("     Password: OwnerPassword123!")
        self.stdout.write("     Role:     Document Owner (Upload, grant, edit, revoke)")
        self.stdout.write("  3. Viewer:")
        self.stdout.write("     Username: viewer_demo")
        self.stdout.write("     Password: ViewerPassword123!")
        self.stdout.write("     Role:     Viewer (Inspect shared docs, download, edit)")
        self.stdout.write("=" * 70 + "\n")
