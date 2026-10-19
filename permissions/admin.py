from django.contrib import admin
from .models import DocumentPermission


@admin.register(DocumentPermission)
class DocumentPermissionAdmin(admin.ModelAdmin):
    """Admin configuration for DocumentPermission monitoring."""

    list_display = ('document', 'user', 'permission_type', 'granted_by', 'created_at', 'updated_at')
    list_filter = ('permission_type', 'created_at')
    search_fields = ('document__name', 'user__username', 'granted_by__username')
    readonly_fields = ('uuid', 'created_at', 'updated_at')
    ordering = ('-created_at',)
