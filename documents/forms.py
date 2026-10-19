"""
Forms for document upload and metadata management in TrustVault.
"""

from django import forms
from django.conf import settings
from .models import Document, DocumentCategory


class DocumentUploadForm(forms.Form):
    """Secure form for uploading new documents."""

    name = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g., Q3 Financial Audit Report',
            'autofocus': True,
        }),
        help_text='User-friendly title for this document.'
    )
    category = forms.ChoiceField(
        choices=DocumentCategory.choices,
        initial=DocumentCategory.GENERAL,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text='Organizational classification category.'
    )

    def clean_category(self):
        return self.cleaned_data.get('category') or DocumentCategory.GENERAL
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional description of document contents or purpose...',
        })
    )
    file = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'data-max-size': str(getattr(settings, 'MAX_UPLOAD_SIZE_BYTES', 25 * 1024 * 1024)),
        }),
        help_text='Supported formats: PDF, PNG, JPG, TXT, DOCX, DOC (Max 25 MB).'
    )


class DocumentMetadataEditForm(forms.ModelForm):
    """Form for editing user-facing document metadata (excluding binary file)."""

    class Meta:
        model = Document
        fields = ('name', 'category', 'description')
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }
