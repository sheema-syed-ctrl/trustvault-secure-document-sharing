"""
Centralized Permission Engine for TrustVault.
Enforces default-deny, server-side object authorization.
Evaluates document ownership, granular READ and EDIT permissions, and cross-user isolation.
"""

import logging
from typing import Optional
from django.db import transaction
from django.db.models import Q, QuerySet
from django.core.exceptions import PermissionDenied, ValidationError
from documents.models import Document
from .models import DocumentPermission, PermissionType

logger = logging.getLogger('trustvault')


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
    def grant_permission(
        cls,
        actor,
        document: Document,
        target_user,
        permission_type: str
    ) -> DocumentPermission:
        """
        Grants or updates access to a document for a target user.
        Strictly restricted to the Document Owner at the service layer.
        """
        if not cls.can_manage_permissions(actor, document):
            logger.warning(
                f"Unauthorized permission grant attempt: User '{actor.username}' (ID: {actor.pk}) "
                f"attempted to grant access to document {document.pk} owned by '{document.owner.username}'."
            )
            raise PermissionDenied("Access denied: Only the document owner can grant permissions for this document.")

        if not target_user:
            raise ValidationError("Invalid recipient: Recipient does not exist.")

        if not getattr(target_user, 'is_active', False):
            raise ValidationError("Invalid recipient: Recipient account is inactive or disabled.")

        if actor.pk == target_user.pk or document.owner_id == target_user.pk:
            raise ValidationError("Invalid recipient: User cannot share a document with themselves.")

        if permission_type not in PermissionType.values:
            raise ValidationError(f"Invalid permission type: '{permission_type}'.")

        with transaction.atomic():
            permission, created = DocumentPermission.objects.update_or_create(
                document=document,
                user=target_user,
                defaults={
                    'permission_type': permission_type,
                    'granted_by': actor,
                }
            )

        action = "granted" if created else "updated"
        logger.info(
            f"Permission {action}: Actor '{actor.username}' (ID: {actor.pk}) {action} {permission_type} "
            f"to '{target_user.username}' (ID: {target_user.pk}) on document {document.pk} ('{document.name}')."
        )
        return permission

    @classmethod
    def update_permission(
        cls,
        actor,
        document: Document,
        permission_id: int,
        new_permission_type: str
    ) -> DocumentPermission:
        """
        Updates the permission level of an existing recipient on a document.
        Strictly restricted to the Document Owner at the service layer.
        Enforces cross-document IDOR validation.
        """
        if not cls.can_manage_permissions(actor, document):
            logger.warning(
                f"Unauthorized permission update attempt: User '{actor.username}' (ID: {actor.pk}) "
                f"attempted to update permission {permission_id} on document {document.pk}."
            )
            raise PermissionDenied("Access denied: Only the document owner can modify permissions.")

        if new_permission_type not in PermissionType.values:
            raise ValidationError(f"Invalid permission type: '{new_permission_type}'.")

        try:
            permission = DocumentPermission.objects.select_related('user', 'document').get(
                pk=permission_id,
                document=document
            )
        except DocumentPermission.DoesNotExist:
            if DocumentPermission.objects.filter(pk=permission_id).exists():
                logger.warning(
                    f"Cross-document permission update attempt: Actor '{actor.username}' (ID: {actor.pk}) "
                    f"attempted to modify permission {permission_id} via document {document.pk}."
                )
            raise PermissionDenied("Access denied: Permission record not found or does not belong to this document.")

        if not permission.user.is_active:
            raise ValidationError("Cannot update permission: Recipient account is inactive.")

        old_type = permission.permission_type
        with transaction.atomic():
            permission.permission_type = new_permission_type
            permission.granted_by = actor
            permission.save()

        logger.info(
            f"Permission updated: Actor '{actor.username}' (ID: {actor.pk}) changed permission "
            f"from {old_type} to {new_permission_type} for '{permission.user.username}' (ID: {permission.user.pk}) "
            f"on document {document.pk} ('{document.name}')."
        )
        return permission

    @classmethod
    def revoke_permission(cls, actor, document: Document, target_user) -> bool:
        """
        Revokes a granted permission on a document for a target user.
        Strictly restricted to the Document Owner at the service layer.
        """
        if not cls.can_manage_permissions(actor, document):
            logger.warning(
                f"Unauthorized permission revocation attempt: User '{actor.username}' (ID: {actor.pk}) "
                f"attempted to revoke permission on document {document.pk}."
            )
            raise PermissionDenied("Access denied: Only the document owner can revoke permissions for this document.")

        deleted_count, _ = DocumentPermission.objects.filter(
            document=document,
            user=target_user
        ).delete()

        if deleted_count > 0:
            target_name = getattr(target_user, 'username', str(target_user))
            target_pk = getattr(target_user, 'pk', 'unknown')
            logger.info(
                f"Permission revoked: Actor '{actor.username}' (ID: {actor.pk}) revoked access "
                f"for '{target_name}' (ID: {target_pk}) on document {document.pk} ('{document.name}')."
            )
        return deleted_count > 0

    @classmethod
    def revoke_permission_by_id(cls, actor, document: Document, permission_id: int) -> bool:
        """
        Revokes a permission by its permission record ID.
        Strictly restricted to the Document Owner at the service layer.
        Enforces cross-document IDOR validation.
        """
        if not cls.can_manage_permissions(actor, document):
            logger.warning(
                f"Unauthorized permission revocation attempt: User '{actor.username}' (ID: {actor.pk}) "
                f"attempted to revoke permission {permission_id} on document {document.pk}."
            )
            raise PermissionDenied("Access denied: Only the document owner can revoke permissions for this document.")

        perm = DocumentPermission.objects.filter(pk=permission_id).select_related('user').first()
        if not perm:
            # Repeated revocation or non-existent record handled gracefully
            return False

        if perm.document_id != document.pk:
            logger.warning(
                f"Cross-document permission revocation attempt: Actor '{actor.username}' (ID: {actor.pk}) "
                f"attempted to revoke permission {permission_id} (belonging to doc {perm.document_id}) "
                f"via document {document.pk}."
            )
            raise PermissionDenied("Access denied: Permission does not belong to this document.")

        target_name = perm.user.username
        target_pk = perm.user.pk
        perm.delete()

        logger.info(
            f"Permission revoked: Actor '{actor.username}' (ID: {actor.pk}) revoked access "
            f"for '{target_name}' (ID: {target_pk}) on document {document.pk} ('{document.name}')."
        )
        return True

    @classmethod
    def search_shareable_users(
        cls,
        actor,
        document: Document,
        query: str = '',
        limit: int = 20
    ) -> QuerySet:
        """
        Searches active registered users eligible to receive document access.
        Strictly restricted to the Document Owner.
        Excludes the document owner / actor and inactive accounts.
        Limits returned results to prevent user enumeration.
        """
        if not cls.can_manage_permissions(actor, document):
            logger.warning(
                f"Unauthorized user lookup attempt: User '{actor.username}' (ID: {actor.pk}) "
                f"attempted recipient lookup for document {document.pk}."
            )
            raise PermissionDenied("Access denied: Only the document owner can search recipients for this document.")

        from django.contrib.auth import get_user_model
        UserModel = get_user_model()

        qs = UserModel.objects.filter(is_active=True).exclude(pk=document.owner_id).exclude(pk=actor.pk)

        if query:
            qs = qs.filter(
                Q(username__icontains=query) |
                Q(email__icontains=query)
            )

        safe_limit = min(max(1, limit), 50)
        return qs.only('id', 'username', 'role').order_by('username')[:safe_limit]

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
