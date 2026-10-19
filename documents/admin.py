from django.contrib import admin
from .models import Document


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    """
    Read-only admin configuration for Document metadata audit inspection.
    Prevents administrative tampering with document ownership, metadata, or storage references.
    """

    list_display = ('name', 'category', 'owner', 'file_size', 'mime_type', 'created_at')
    list_filter = ('category', 'created_at', 'mime_type')
    search_fields = ('name', 'description', 'original_filename', 'owner__username')
    readonly_fields = (
        'uuid', 'name', 'description', 'category', 'owner',
        'original_filename', 'storage_filename', 'file_size',
        'mime_type', 'sha256_hash', 'created_at', 'updated_at'
    )
    ordering = ('-created_at',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
