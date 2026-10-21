"""
Database models for TrustVault's persistent audit trail engine.
Records all security-relevant document and permission lifecycle activities.
Guarantees append-only persistence, historical snapshot preservation,
and defense against tampering.
"""

import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError


class AuditEventType(models.TextChoices):
    """Document and permission activity event types."""
    # Document lifecycle
    DOCUMENT_UPLOADED = 'DOCUMENT_UPLOADED', _('Document Uploaded')
    DOCUMENT_DOWNLOADED = 'DOCUMENT_DOWNLOADED', _('Document Downloaded')
    DOCUMENT_UPDATED = 'DOCUMENT_UPDATED', _('Document Updated')
    DOCUMENT_DELETED = 'DOCUMENT_DELETED', _('Document Deleted')

    # Object-level permission lifecycle
    PERMISSION_GRANTED = 'PERMISSION_GRANTED', _('Permission Granted')
    PERMISSION_UPDATED = 'PERMISSION_UPDATED', _('Permission Updated')
    PERMISSION_REVOKED = 'PERMISSION_REVOKED', _('Permission Revoked')

    # Security & authorization monitoring
    SECURITY_ACCESS_DENIED = 'SECURITY_ACCESS_DENIED', _('Security Access Denied')


class AuditStatus(models.TextChoices):
    """Execution status or outcome of audited event."""
    SUCCESS = 'SUCCESS', _('Success')
    FAILURE = 'FAILURE', _('Failure')
    WARNING = 'WARNING', _('Warning')


class AuditQuerySet(models.QuerySet):
    """
    Append-only QuerySet enforcing immutable audit records.
    Explicitly intercepts and blocks bulk modification and deletion operations.
    """

    def update(self, **kwargs):
        raise ValidationError("AuditEvent records are append-only and cannot be modified via bulk operations.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError("AuditEvent records are append-only and cannot be modified via bulk operations.")

    def delete(self):
        raise ValidationError("AuditEvent records are immutable and cannot be deleted via bulk operations.")


class AuditManager(models.Manager.from_queryset(AuditQuerySet)):
    """
    Manager for AuditEvent enforcing tamper resistance across both instance and queryset levels.
    """
    pass


class AuditEvent(models.Model):
    """
    Persistent, tamper-resistant record of document and permission events.
    Key properties:
      - Append-only model logic (save on existing records and delete calls raise ValidationError).
      - Historical snapshots: retains username, document name, and document ID even if
        the foreign-key entity is subsequently removed.
      - Never stores passwords, tokens, session IDs, CSRF tokens, or private file contents.
    """

    objects = AuditManager()

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    event_type = models.CharField(
        max_length=50,
        choices=AuditEventType.choices,
        db_index=True,
        help_text=_("Categorical activity type.")
    )
    status = models.CharField(
        max_length=20,
        choices=AuditStatus.choices,
        default=AuditStatus.SUCCESS,
        db_index=True,
        help_text=_("Outcome or security status.")
    )

    # Actor reference and historical snapshot
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events_as_actor',
        help_text=_("User who performed the action (NULL for system/anonymous).")
    )
    actor_username = models.CharField(
        max_length=150,
        blank=True,
        help_text=_("Historical snapshot of actor username for forensic auditability.")
    )

    # Target document reference and historical snapshots
    target_document = models.ForeignKey(
        'documents.Document',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events',
        help_text=_("Target document (SET_NULL on document deletion to preserve event).")
    )
    target_document_id_snapshot = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("Historical snapshot of document primary key.")
    )
    target_document_name_snapshot = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Historical snapshot of document name.")
    )

    # Target recipient reference and historical snapshot
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_events_as_target',
        help_text=_("Recipient user receiving or losing document access.")
    )
    target_username = models.CharField(
        max_length=150,
        blank=True,
        help_text=_("Historical snapshot of recipient username.")
    )

    # Permission delta fields
    previous_permission = models.CharField(
        max_length=20,
        blank=True,
        help_text=_("Prior permission level (e.g. READ, EDIT) where applicable.")
    )
    new_permission = models.CharField(
        max_length=20,
        blank=True,
        help_text=_("New permission level (e.g. READ, EDIT) where applicable.")
    )

    # Temporal, network, and contextual metadata
    timestamp = models.DateTimeField(
        default=timezone.now,
        db_index=True,
        help_text=_("Timezone-aware timestamp of event occurrence.")
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text=_("Client IP address where available.")
    )
    user_agent = models.CharField(
        max_length=512,
        blank=True,
        help_text=_("Sanitized client user agent string.")
    )
    correlation_id = models.CharField(
        max_length=64,
        blank=True,
        help_text=_("Request or transaction correlation identifier.")
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Sanitized non-sensitive structured metadata (never contains secrets).")
    )

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'event_type'], name='idx_audit_time_type'),
            models.Index(fields=['target_document', 'event_type'], name='idx_audit_doc_type'),
            models.Index(fields=['actor', 'timestamp'], name='idx_audit_actor_time'),
            models.Index(fields=['target_user', 'timestamp'], name='idx_audit_target_time'),
            models.Index(fields=['event_type', 'status'], name='idx_audit_type_status'),
        ]

    def clean(self):
        super().clean()
        if self.event_type not in AuditEventType.values:
            raise ValidationError(f"Invalid audit event type: '{self.event_type}'.")
        if self.status not in AuditStatus.values:
            raise ValidationError(f"Invalid audit status: '{self.status}'.")

    def save(self, *args, **kwargs):
        # Enforce append-only immutability: once saved, an AuditEvent cannot be updated
        if self.pk is not None and not kwargs.get('force_insert', False):
            if AuditEvent.objects.filter(pk=self.pk).exists():
                raise ValidationError("AuditEvent records are append-only and cannot be modified.")

        # Ensure historical snapshots are populated
        if self.actor and not self.actor_username:
            self.actor_username = getattr(self.actor, 'username', '')
        if self.target_document:
            if not self.target_document_id_snapshot:
                self.target_document_id_snapshot = self.target_document.pk
            if not self.target_document_name_snapshot:
                self.target_document_name_snapshot = self.target_document.name
        if self.target_user and not self.target_username:
            self.target_username = getattr(self.target_user, 'username', '')

        self.full_clean()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Enforce immutability: AuditEvent records cannot be deleted via ORM
        raise ValidationError("AuditEvent records are immutable and cannot be deleted.")

    def __str__(self):
        actor_name = self.actor_username or (self.actor.username if self.actor else 'SYSTEM')
        doc_name = self.target_document_name_snapshot or (f"Doc#{self.target_document_id_snapshot}" if self.target_document_id_snapshot else 'N/A')
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.event_type} by {actor_name} on {doc_name} ({self.status})"
