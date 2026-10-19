"""
Document database model for TrustVault.
Represents uploaded confidential files with integrity hashes, detected MIME types,
and secure storage identifiers.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _


class DocumentCategory(models.TextChoices):
    """Categorical classification for vault documents."""
    FINANCIAL = 'FINANCIAL', _('Financial & Accounting')
    LEGAL = 'LEGAL', _('Legal & Compliance')
    TECHNICAL = 'TECHNICAL', _('Technical & Architecture')
    HR = 'HR', _('Human Resources')
    GENERAL = 'GENERAL', _('General / Operational')


class Document(models.Model):
    """
    Core document model.
    Guarantees:
      - Association with authenticated Document Owner.
      - Segregated physical storage filename (UUID-based, avoiding filename collisions & path traversal).
      - Integrity verification via SHA-256 digest.
      - Never directly exposed via public static or media URLs.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255, help_text=_('User-facing document name.'))
    description = models.TextField(blank=True, default='', help_text=_('Optional document description.'))
    category = models.CharField(
        max_length=20,
        choices=DocumentCategory.choices,
        default=DocumentCategory.GENERAL,
        help_text=_('Classification category.')
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='documents',
        help_text=_('Authenticated user who owns and manages this document.')
    )
    original_filename = models.CharField(max_length=255, help_text=_('Sanitized original file name.'))
    storage_filename = models.CharField(max_length=255, unique=True, help_text=_('Unique random internal storage name.'))
    file_size = models.PositiveBigIntegerField(help_text=_('Verified file size in bytes.'))
    mime_type = models.CharField(max_length=120, help_text=_('Verified MIME type from file signature analysis.'))
    sha256_hash = models.CharField(max_length=64, help_text=_('Cryptographic SHA-256 checksum.'))
    created_at = models.DateTimeField(auto_now_add=True, help_text=_('Upload timestamp.'))
    updated_at = models.DateTimeField(auto_now=True, help_text=_('Last metadata update timestamp.'))

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', '-created_at']),
            models.Index(fields=['category']),
            models.Index(fields=['uuid']),
        ]

    def __str__(self):
        return f"{self.name} [{self.get_category_display()}] — Owner: {self.owner.username}"

    @property
    def formatted_size(self) -> str:
        """Returns human-readable representation of file size."""
        bytes_val = self.file_size
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        else:
            return f"{bytes_val / (1024 * 1024):.2f} MB"

    @property
    def file_extension(self) -> str:
        """Extract lowercase extension from original filename."""
        if '.' in self.original_filename:
            return self.original_filename.rsplit('.', 1)[-1].lower()
        return ''
