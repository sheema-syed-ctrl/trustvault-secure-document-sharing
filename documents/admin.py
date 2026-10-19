from django.contrib import admin
from .models import Document


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    """Admin configuration for Document metadata monitoring."""

    list_display = ('name', 'category', 'owner', 'file_size', 'mime_type', 'created_at')
    list_filter = ('category', 'created_at', 'mime_type')
    search_fields = ('name', 'description', 'original_filename', 'owner__username')
    readonly_fields = ('uuid', 'storage_filename', 'file_size', 'mime_type', 'sha256_hash', 'created_at', 'updated_at')
    ordering = ('-created_at',)
