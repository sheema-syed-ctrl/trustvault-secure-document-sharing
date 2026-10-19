"""
Django Admin configuration for TrustVault's persistent audit trail.
Enforces read-only inspection: prevents adding, editing, or deleting audit events.
"""

from django.contrib import admin
from .models import AuditEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    """
    Read-only Django Admin interface for AuditEvent.
    Enforces strict tamper-resistance:
      - Add permission denied.
      - Change permission denied.
      - Delete permission denied.
      - All fields rendered as read-only.
    """

    list_display = (
        'timestamp',
        'event_type',
        'status',
        'actor_username',
        'target_document_name_snapshot',
        'target_username',
        'ip_address',
    )

    list_filter = (
        'event_type',
        'status',
        'timestamp',
    )

    search_fields = (
        'actor_username',
        'target_document_name_snapshot',
        'target_username',
        'uuid',
        'ip_address',
    )

    ordering = ('-timestamp',)

    # Make every single field read-only in the change view
    readonly_fields = (
        'id',
        'uuid',
        'event_type',
        'status',
        'actor',
        'actor_username',
        'target_document',
        'target_document_id_snapshot',
        'target_document_name_snapshot',
        'target_user',
        'target_username',
        'previous_permission',
        'new_permission',
        'timestamp',
        'ip_address',
        'user_agent',
        'correlation_id',
        'metadata',
    )

    def has_add_permission(self, request):
        """Audit records cannot be created manually via Django Admin."""
        return False

    def has_change_permission(self, request, obj=None):
        """Audit records cannot be modified via Django Admin."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit records cannot be deleted via Django Admin."""
        return False
