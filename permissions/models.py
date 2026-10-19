"""
Document permission database models for TrustVault.
Implements granular object-level authorization (READ and EDIT permissions)
associated with specific documents and registered users.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError


class PermissionType(models.TextChoices):
    """Available document access levels."""
    READ = 'READ', _('Read Only (View Metadata and Details)')
    EDIT = 'EDIT', _('Edit (View and Modify Metadata)')


class DocumentPermission(models.Model):
    """
    Object-level permission record granting access to a specific document for a named user.
    Guarantees:
      - Unique constraint per (document, user) pair.
      - Server-side validation of permission type.
      - Prohibits redundant permission records for the document owner.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    document = models.ForeignKey(
        'documents.Document',
        on_delete=models.CASCADE,
        related_name='permissions',
        help_text=_('Target document for which access is granted.')
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='document_permissions',
        help_text=_('Registered user receiving granted access.')
    )
    permission_type = models.CharField(
        max_length=10,
        choices=PermissionType.choices,
        help_text=_('Level of access granted.')
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='granted_document_permissions',
        help_text=_('User who authorized and granted this permission.')
    )
    created_at = models.DateTimeField(auto_now_add=True, help_text=_('Timestamp of permission creation.'))
    updated_at = models.DateTimeField(auto_now=True, help_text=_('Timestamp of last permission modification.'))

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['document', 'user'],
                name='unique_document_user_permission'
            )
        ]
        indexes = [
            models.Index(fields=['document', 'user']),
            models.Index(fields=['user', 'permission_type']),
        ]

    def clean(self):
        super().clean()
        if self.document_id and self.user_id:
            # Document owners have inherent authoritative ownership; permissions are for other users
            if self.document.owner_id == self.user_id:
                raise ValidationError(
                    "Redundant permission: Document owner already possesses inherent, authoritative access."
                )
        if self.document_id and self.granted_by_id:
            # Only the document owner is authorized to grant access to their document
            if self.document.owner_id != self.granted_by_id:
                raise ValidationError(
                    "Unauthorized grantor: Only the document owner can grant permissions for this document."
                )
        if self.permission_type not in PermissionType.values:
            raise ValidationError(f"Invalid permission type: '{self.permission_type}'.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} -> {self.document.name} [{self.get_permission_type_display()}]"
