"""
Document service layer for TrustVault.
Encapsulates all document business logic, storage operations, and transaction boundaries.
"""

import datetime
import logging
import os
import uuid
from pathlib import Path
from django.db import transaction
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.db.models.functions import Lower
from django.db.models.query import QuerySet
from django.utils import timezone
from accounts.services import RBACService
from .models import Document, DocumentCategory
from .validators import validate_file_upload

logger = logging.getLogger('trustvault')


class DocumentService:
    """
    Centralized service for document lifecycle management:
      - Upload and private storage storage isolation
      - Metadata modification
      - Safe physical file deletion
      - Path traversal defenses
    """

    @staticmethod
    def get_protected_storage_path(storage_filename: str) -> Path:
        """
        Resolves internal storage path and ensures the target strictly resides
        within PROTECTED_MEDIA_ROOT, preventing directory traversal and symlink escape.
        """
        root = Path(settings.PROTECTED_MEDIA_ROOT).resolve()
        target = (root / storage_filename).resolve()

        if not target.is_relative_to(root):
            raise PermissionDenied("Security violation: Path traversal or symlink escape attempt detected.")
        return target

    @classmethod
    def get_authorized_file(cls, actor, document_id) -> tuple:
        """
        Retrieves an open read file handle and document instance for authorized download.
        Enforces:
          - Mandatory authentication of actor.
          - Centralized object authorization via PermissionService (READ permission required).
          - Path traversal and symlink validation.
          - Physical file existence verification.
        Returns:
          tuple: (open_binary_file_handle, document_instance)
        Raises:
          PermissionDenied: If actor lacks authentication or READ authorization.
          Document.DoesNotExist: If document is not found.
          FileNotFoundError: If physical storage file is missing from private storage.
        """
        if not actor or not actor.is_authenticated:
            raise PermissionDenied("Authentication required to access documents.")

        document = Document.objects.select_related('owner').get(pk=document_id)

        from permissions.services import PermissionService
        if not PermissionService.can_read(actor, document):
            logger.warning(
                f"Unauthorized download attempt: User '{actor.username}' (ID: {actor.pk}, Role: {actor.role}) "
                f"denied access to document {document.pk} ('{document.name}')."
            )
            raise PermissionDenied("Access denied: You do not have authorization to download this document.")

        target_path = cls.get_protected_storage_path(document.storage_filename)

        if not target_path.exists() or not target_path.is_file():
            logger.error(
                f"Physical storage file missing for authorized document: "
                f"Document ID: {document.pk}, Storage File: {document.storage_filename}, Target: {target_path}"
            )
            raise FileNotFoundError("Storage file could not be located in secure vault.")

        file_handle = open(target_path, 'rb')
        return file_handle, document

    @classmethod
    def upload_document(
        cls,
        owner,
        uploaded_file,
        name: str,
        description: str = '',
        category: str = DocumentCategory.GENERAL
    ) -> Document:
        """
        Validates, saves to private storage, and registers a new Document.
        Atomic operation: cleans up written file if database transaction fails.
        """
        # 1. Authorization: Only Document Owners can upload
        if not (RBACService.is_owner(owner) or owner.is_superuser):
            raise PermissionDenied("Access denied: Only Document Owners are authorized to upload documents.")

        # 2. File Signature & Size Validation
        file_meta = validate_file_upload(uploaded_file)

        # 3. Generate Cryptographically Unique Storage Filename
        storage_filename = f"{uuid.uuid4().hex}.bin"
        target_path = cls.get_protected_storage_path(storage_filename)

        written_to_disk = False
        try:
            # 4. Stream File to Protected Storage (Outside Web Root)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            written_to_disk = True

            # 5. Atomic Database Record Creation & Audit Event
            with transaction.atomic():
                doc = Document.objects.create(
                    name=name.strip(),
                    description=description.strip(),
                    category=category,
                    owner=owner,
                    original_filename=file_meta['clean_filename'],
                    storage_filename=storage_filename,
                    file_size=file_meta['file_size'],
                    mime_type=file_meta['mime_type'],
                    sha256_hash=file_meta['sha256']
                )
                from audit.services import AuditService
                AuditService.log_document_uploaded(actor=owner, document=doc)
                return doc

        except Exception as exc:
            # Cleanup orphan file from disk if DB creation or writing failed
            if written_to_disk and target_path.exists():
                try:
                    os.remove(target_path)
                except OSError:
                    pass
            raise exc

    @classmethod
    def update_document_metadata(
        cls,
        document: Document,
        actor,
        name: str,
        description: str,
        category: str
    ) -> Document:
        """
        Modifies user-facing document metadata.
        Restricted to the document owner or users with explicit EDIT permission.
        """
        from permissions.services import PermissionService
        if not PermissionService.can_edit(actor, document):
            raise PermissionDenied("Access denied: You do not have authorization to edit this document.")

        with transaction.atomic():
            document.name = name.strip()
            document.description = description.strip()
            document.category = category
            document.save(update_fields=['name', 'description', 'category', 'updated_at'])
            from audit.services import AuditService
            AuditService.log_document_updated(actor=actor, document=document)

        return document

    @classmethod
    def delete_document(cls, document: Document, actor) -> bool:
        """
        Deletes a document record and safely removes the physical storage file.
        Strictly restricted to the document owner.

        Consistency guarantee:
          - Database record deletion is executed within an atomic transaction.
          - Audit log record is captured within the same atomic transaction.
          - Physical file cleanup is deferred until the database transaction commits
            successfully via transaction.on_commit().
          - If the database transaction fails/rolls back, the disk file is preserved.
          - If disk file cleanup encounters an error post-commit, an error log is emitted
            for administrative/audit reconciliation without rolling back database state.
        """
        from permissions.services import PermissionService
        if not PermissionService.can_delete(actor, document):
            raise PermissionDenied("Access denied: Only the document owner can delete this document.")

        target_path = cls.get_protected_storage_path(document.storage_filename)
        storage_filename = document.storage_filename
        doc_id = document.pk
        doc_name = document.name

        def cleanup_physical_file():
            if target_path.exists():
                try:
                    os.remove(target_path)
                    logger.info(f"Purged storage file {storage_filename} for deleted document {doc_id}.")
                except OSError as err:
                    logger.error(
                        f"CRITICAL: Failed to remove physical file from storage post-commit. "
                        f"Document ID: {doc_id}, Storage File: {storage_filename}, Path: {target_path}. "
                        f"Error: {err}"
                    )
            else:
                logger.warning(
                    f"Physical storage file already absent during deletion cleanup. "
                    f"Document ID: {doc_id}, Storage File: {storage_filename}"
                )

        with transaction.atomic():
            from audit.services import AuditService
            AuditService.log_document_deleted(
                actor=actor,
                document_id=doc_id,
                document_name=doc_name
            )
            document.delete()
            transaction.on_commit(cleanup_physical_file)

        return True

    @classmethod
    def search_and_filter_documents(
        cls,
        user,
        query: str = '',
        category: str = '',
        owner_username: str = '',
        date_from=None,
        date_to=None,
        sort_by: str = 'newest'
    ) -> QuerySet:
        """
        Executes authorized document discovery, multi-factor filtering, and injection-safe sorting.

        Security & Integrity Guarantees:
          - Authorization-first evaluation via PermissionService.get_accessible_documents(user).
          - Anonymous/unauthenticated actors immediately receive an empty QuerySet.
          - Multi-field substring search across name, description, original_filename,
            owner username, and category labels.
          - Binary document file contents are strictly excluded from search indexing.
          - Whitelist-enforced sorting preventing SQL or column injection.
          - Date boundaries are validated and timezone-aware; inverted ranges raise ValidationError.
          - Malformed or excessively long queries (>100 characters) are safely sanitized and truncated.
        """
        if not user or not user.is_authenticated:
            return Document.objects.none()

        from permissions.services import PermissionService
        qs = PermissionService.get_accessible_documents(user).select_related('owner')

        # 1. Text Search Across Metadata Fields
        if query and isinstance(query, str):
            clean_query = query.strip()[:100]
            if clean_query:
                search_q = (
                    Q(name__icontains=clean_query) |
                    Q(description__icontains=clean_query) |
                    Q(original_filename__icontains=clean_query) |
                    Q(owner__username__icontains=clean_query)
                )

                # Match against category human-readable display names or keys
                matching_cats = [
                    code for code, label in DocumentCategory.choices
                    if clean_query.lower() in str(label).lower() or clean_query.lower() == str(code).lower()
                ]
                if matching_cats:
                    search_q |= Q(category__in=matching_cats)

                qs = qs.filter(search_q)

        # 2. Category Filter
        if category and isinstance(category, str):
            category = category.strip()
            if category:
                if category in DocumentCategory.values:
                    qs = qs.filter(category=category)
                else:
                    return qs.none()

        # 3. Owner Username Filter
        if owner_username and isinstance(owner_username, str):
            owner_clean = owner_username.strip()[:150]
            if owner_clean:
                qs = qs.filter(owner__username=owner_clean)

        # 4. Timezone-Aware Upload Date Filters
        parsed_date_from = None
        parsed_date_to = None

        if date_from:
            if isinstance(date_from, (datetime.date, datetime.datetime)):
                parsed_date_from = date_from if isinstance(date_from, datetime.date) else date_from.date()
            elif isinstance(date_from, str) and date_from.strip():
                try:
                    parsed_date_from = datetime.datetime.strptime(date_from.strip(), '%Y-%m-%d').date()
                except ValueError:
                    raise ValidationError("Invalid start date format. Expected YYYY-MM-DD.")

        if date_to:
            if isinstance(date_to, (datetime.date, datetime.datetime)):
                parsed_date_to = date_to if isinstance(date_to, datetime.date) else date_to.date()
            elif isinstance(date_to, str) and date_to.strip():
                try:
                    parsed_date_to = datetime.datetime.strptime(date_to.strip(), '%Y-%m-%d').date()
                except ValueError:
                    raise ValidationError("Invalid end date format. Expected YYYY-MM-DD.")

        if parsed_date_from and parsed_date_to and parsed_date_from > parsed_date_to:
            raise ValidationError("Invalid date range: Start date cannot be after end date.")

        current_tz = timezone.get_current_timezone()
        if parsed_date_from:
            dt_from = timezone.make_aware(
                datetime.datetime.combine(parsed_date_from, datetime.time.min),
                current_tz
            )
            qs = qs.filter(created_at__gte=dt_from)

        if parsed_date_to:
            dt_to = timezone.make_aware(
                datetime.datetime.combine(parsed_date_to, datetime.time.max),
                current_tz
            )
            qs = qs.filter(created_at__lte=dt_to)

        # 5. Injection-Safe Sorting
        sort_mapping = {
            'newest': ['-created_at'],
            'oldest': ['created_at'],
            'name_asc': [Lower('name').asc(), '-created_at'],
            'name_desc': [Lower('name').desc(), '-created_at'],
            'updated': ['-updated_at', '-created_at'],
        }
        order_fields = sort_mapping.get(sort_by, sort_mapping['newest'])

        return qs.order_by(*order_fields).distinct()
