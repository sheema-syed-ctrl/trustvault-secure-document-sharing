"""
Centralized Permission Engine for TrustVault.
Enforces default-deny, server-side object authorization.
Evaluates document ownership, granular READ and EDIT permissions, and cross-user isolation.
"""

from typing import Optional
from django.db.models import Q, QuerySet
from documents.models import Document
from .models import DocumentPermission, PermissionType


class PermissionService:
    """
    Centralized object-level authorization service.
    Guarantees:
      - Default-deny architecture.
      - Document ownership takes precedence.
      - EDIT permission strictly includes READ access.
      - READ permission explicitly does NOT allow editing.
      - Neither READ nor EDIT permission grants document deletion or permission management.
      - Administrators do NOT automatically inherit document access.
      - Anonymous users are always rejected.
    """

    @classmethod
    def can_read(cls, user, document: Document) -> bool:
        """
        Determines whether a user is authorized to view document metadata and content.
        Granted to:
          - Document Owner.
          - Users explicitly granted READ or EDIT permission.
        """
        if not user or not user.is_authenticated or not document:
            return False

        # 1. Document Owner has inherent read capability
        if document.owner_id == user.pk:
            return True

        # 2. Check for explicit permission grant (READ or EDIT)
        return DocumentPermission.objects.filter(
            document=document,
            user=user,
            permission_type__in=[PermissionType.READ, PermissionType.EDIT]
        ).exists()

    @classmethod
    def can_edit(cls, user, document: Document) -> bool:
        """
        Determines whether a user is authorized to modify document metadata.
        Granted to:
          - Document Owner.
          - Users explicitly granted EDIT permission.
        Denied to:
          - Users with only READ permission.
          - Administrators without explicit authorization.
        """
        if not user or not user.is_authenticated or not document:
            return False

        # 1. Document Owner has authoritative edit capability
        if document.owner_id == user.pk:
            return True

        # 2. Check for explicit EDIT permission grant
        return DocumentPermission.objects.filter(
            document=document,
            user=user,
            permission_type=PermissionType.EDIT
        ).exists()

    @classmethod
    def can_delete(cls, user, document: Document) -> bool:
        """
        Determines whether a user is authorized to delete a document and purge storage.
        Strictly restricted to the Document Owner.
        EDIT and READ grantees cannot delete documents under any circumstance.
        """
        if not user or not user.is_authenticated or not document:
            return False

        return document.owner_id == user.pk

    @classmethod
    def can_manage_permissions(cls, user, document: Document) -> bool:
        """
        Determines whether a user is authorized to grant, modify, or revoke permissions.
        Strictly restricted to the Document Owner.
        """
        if not user or not user.is_authenticated or not document:
            return False

        return document.owner_id == user.pk

    @classmethod
    def has_permission(cls, user, document: Document, permission_type: str) -> bool:
        """
        Generic permission validation for a specific permission type.
        """
        if permission_type == PermissionType.READ:
            return cls.can_read(user, document)
        elif permission_type == PermissionType.EDIT:
            return cls.can_edit(user, document)
        return False

    @classmethod
    def get_effective_permission(cls, user, document: Document) -> Optional[str]:
        """
        Returns the highest effective permission level for the user on the document.
        Returns 'OWNER', 'EDIT', 'READ', or None.
        """
        if not user or not user.is_authenticated or not document:
            return None

        if document.owner_id == user.pk:
            return 'OWNER'

        perm = DocumentPermission.objects.filter(document=document, user=user).first()
        if perm:
            return perm.permission_type
        return None

    @classmethod
    def get_accessible_documents(cls, user, min_permission: str = PermissionType.READ) -> QuerySet:
        """
        Returns a QuerySet of all documents accessible to the given user based on
        ownership or explicit permission grants.
        """
        if not user or not user.is_authenticated:
            return Document.objects.none()

        if min_permission == PermissionType.EDIT:
            return Document.objects.filter(
                Q(owner=user) |
                Q(permissions__user=user, permissions__permission_type=PermissionType.EDIT)
            ).distinct()

        # Default READ: owned OR shared with any valid permission
        return Document.objects.filter(
            Q(owner=user) |
            Q(permissions__user=user)
        ).distinct()
