"""
Document service layer for TrustVault.
Encapsulates all document business logic, storage operations, and transaction boundaries.
"""

import logging
import os
import uuid
from pathlib import Path
from django.db import transaction
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
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
        within PROTECTED_MEDIA_ROOT, preventing directory traversal.
        """
        root = Path(settings.PROTECTED_MEDIA_ROOT).resolve()
        target = (root / storage_filename).resolve()

        if not str(target).startswith(str(root)):
            raise PermissionDenied("Security violation: Path traversal attempt detected.")
        return target

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

            # 5. Atomic Database Record Creation
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

        document.name = name.strip()
        document.description = description.strip()
        document.category = category
        document.save(update_fields=['name', 'description', 'category', 'updated_at'])
        return document

    @classmethod
    def delete_document(cls, document: Document, actor) -> bool:
        """
        Deletes a document record and safely removes the physical storage file.
        Strictly restricted to the document owner.

        Consistency guarantee:
          - Database record deletion is executed within an atomic transaction.
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
            document.delete()
            transaction.on_commit(cleanup_physical_file)

        return True
