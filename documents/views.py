"""
Document management views for TrustVault.
Implements document listing, secure upload, metadata inspection, editing, and deletion.
Enforces centralized server-side object authorization via PermissionService.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from accounts.decorators import owner_required
from permissions.services import PermissionService
from .models import Document, DocumentCategory
from .forms import DocumentUploadForm, DocumentMetadataEditForm
from .services import DocumentService


@login_required
def document_list_view(request):
    """
    Displays accessible documents authorized under the Permission Engine:
      - Document Owners see their owned documents.
      - Users with explicit READ or EDIT grants see shared documents.
      - Administrators see only documents they own or have been explicitly granted.
    """
    user = request.user
    category_filter = request.GET.get('category', '').strip()
    search_query = request.GET.get('q', '').strip()

    # Query authorized documents using centralized PermissionService
    documents_qs = PermissionService.get_accessible_documents(user)

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
    Enforces centralized object-level authorization: READ permission required.
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization check via PermissionService
    if not PermissionService.can_read(request.user, document):
        raise PermissionDenied("Access denied: You do not have authorization to view this document.")

    can_edit = PermissionService.can_edit(request.user, document)
    can_delete = PermissionService.can_delete(request.user, document)
    can_manage_permissions = PermissionService.can_manage_permissions(request.user, document)
    effective_permission = PermissionService.get_effective_permission(request.user, document)

    return render(request, 'documents/document_detail.html', {
        'document': document,
        'can_edit': can_edit,
        'can_delete': can_delete,
        'can_manage_permissions': can_manage_permissions,
        'effective_permission': effective_permission,
        'is_owner': (document.owner == request.user),
    })


@login_required
def document_edit_view(request, doc_id):
    """
    Modifies document metadata (Name, Description, Category).
    Restricted to Document Owner or users with explicit EDIT permission.
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization check via PermissionService
    if not PermissionService.can_edit(request.user, document):
        raise PermissionDenied("Access denied: You do not have permission to edit this document.")

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
    Strictly restricted to the Document Owner.
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization check via PermissionService
    if not PermissionService.can_delete(request.user, document):
        raise PermissionDenied("Access denied: Only the document owner can delete this document.")

    name = document.name
    DocumentService.delete_document(document=document, actor=request.user)
    messages.success(request, f"Document '{name}' and its secured storage file have been deleted.")
    return redirect('documents:list')
