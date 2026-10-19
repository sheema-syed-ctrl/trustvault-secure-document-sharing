"""
Document management views for TrustVault.
Implements document listing, secure upload, metadata management, and deletion.
Enforces strict server-side owner isolation and default-deny authorization.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from accounts.decorators import owner_required
from .models import Document, DocumentCategory
from .forms import DocumentUploadForm, DocumentMetadataEditForm
from .services import DocumentService


@login_required
def document_list_view(request):
    """
    Displays accessible documents based on user role:
      - Document Owners see their own uploaded documents.
      - Administrators see metadata index for audit/management (no file downloads).
      - Viewers see empty list (until Phase 04/06 permissions engine).
    """
    user = request.user
    category_filter = request.GET.get('category', '').strip()
    search_query = request.GET.get('q', '').strip()

    if user.is_owner_role:
        documents_qs = Document.objects.filter(owner=user)
    elif user.is_admin_role:
        documents_qs = Document.objects.all()
    else:
        # Viewers have not been granted explicit permissions yet (Phase 04/06)
        documents_qs = Document.objects.none()

    if category_filter:
        documents_qs = documents_qs.filter(category=category_filter)

    if search_query:
        documents_qs = documents_qs.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(original_filename__icontains=search_query)
        )

    paginator = Paginator(documents_qs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'documents/document_list.html', {
        'page_obj': page_obj,
        'categories': DocumentCategory.choices,
        'selected_category': category_filter,
        'search_query': search_query,
        'total_count': documents_qs.count(),
    })


@owner_required
def document_upload_view(request):
    """
    Uploads a confidential document to private storage.
    Strictly restricted to Document Owners.
    Validates file signatures, file sizes, and extensions.
    """
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                document = DocumentService.upload_document(
                    owner=request.user,
                    uploaded_file=request.FILES['file'],
                    name=form.cleaned_data['name'],
                    description=form.cleaned_data['description'],
                    category=form.cleaned_data['category']
                )
                messages.success(request, f"Document '{document.name}' successfully uploaded and secured in vault.")
                return redirect('documents:detail', doc_id=document.id)
            except ValidationError as exc:
                form.add_error('file', exc.message)
            except Exception as exc:
                messages.error(request, f"Upload failed: {str(exc)}")
    else:
        form = DocumentUploadForm()

    return render(request, 'documents/document_upload.html', {'form': form})


@login_required
def document_detail_view(request, doc_id):
    """
    Displays comprehensive document metadata (size, hash, MIME type, upload timestamp).
    Enforces cross-owner isolation: Users can view details only for their own documents.
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization check
    if document.owner != request.user and not request.user.is_admin_role:
        raise PermissionDenied("Access denied: You do not have authorization to view this document's details.")

    return render(request, 'documents/document_detail.html', {
        'document': document,
        'is_owner': (document.owner == request.user),
    })


@login_required
def document_edit_view(request, doc_id):
    """
    Modifies document metadata (Name, Description, Category).
    Strictly restricted to the document owner.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if document.owner != request.user and not request.user.is_superuser:
        raise PermissionDenied("Access denied: Only the document owner can edit document metadata.")

    if request.method == 'POST':
        form = DocumentMetadataEditForm(request.POST, instance=document)
        if form.is_valid():
            DocumentService.update_document_metadata(
                document=document,
                actor=request.user,
                name=form.cleaned_data['name'],
                description=form.cleaned_data['description'],
                category=form.cleaned_data['category']
            )
            messages.success(request, f"Metadata for '{document.name}' has been updated.")
            return redirect('documents:detail', doc_id=document.id)
    else:
        form = DocumentMetadataEditForm(instance=document)

    return render(request, 'documents/document_edit.html', {
        'form': form,
        'document': document,
    })


@login_required
@require_POST
def document_delete_view(request, doc_id):
    """
    Deletes a document and safely cleans up its physical storage file.
    Strictly restricted to the document owner.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if document.owner != request.user and not request.user.is_superuser:
        raise PermissionDenied("Access denied: Only the document owner can delete this document.")

    name = document.name
    DocumentService.delete_document(document=document, actor=request.user)
    messages.success(request, f"Document '{name}' and its secured storage file have been deleted.")
    return redirect('documents:list')
