from django.contrib import admin
from .models import DocumentPermission


@admin.register(DocumentPermission)
class DocumentPermissionAdmin(admin.ModelAdmin):
    """
    Read-only admin configuration for DocumentPermission audit inspection.
    Enforces security boundary: Administrators cannot grant, alter, or delete
    document permissions via Django Admin, preserving the Document Owner's
    exclusive authorization authority and preventing privilege escalation.
    """

    list_display = ('document', 'user', 'permission_type', 'granted_by', 'created_at', 'updated_at')
    list_filter = ('permission_type', 'created_at')
    search_fields = ('document__name', 'user__username', 'granted_by__username')
    readonly_fields = (
        'uuid', 'document', 'user', 'permission_type',
        'granted_by', 'created_at', 'updated_at'
    )
    ordering = ('-created_at',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
