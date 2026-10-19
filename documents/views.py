"""
Document management views for TrustVault.
Implements document listing, secure upload, metadata inspection, editing, and deletion.
Enforces centralized server-side object authorization via PermissionService.
"""

import logging
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_http_methods
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from accounts.decorators import owner_required
from permissions.services import PermissionService
from .models import Document, DocumentCategory
from .forms import DocumentUploadForm, DocumentMetadataEditForm
from .services import DocumentService
from .validators import sanitize_filename

logger = logging.getLogger('trustvault')


@login_required
def document_list_view(request):
    """
    Displays accessible documents authorized under the Permission Engine:
      - Document Owners see their owned documents.
      - Users with explicit READ or EDIT grants see shared documents.
      - Administrators see only documents they own or have been explicitly granted.
    Supports comprehensive search, multi-factor filtering, injection-safe sorting, and pagination.
    """
    user = request.user
    search_query = request.GET.get('q', '').strip()
    category_filter = request.GET.get('category', '').strip()
    owner_filter = request.GET.get('owner', '').strip()
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw = request.GET.get('date_to', '').strip()
    sort_by = request.GET.get('sort', 'newest').strip()

    # Determine available owners ONLY from user's accessible documents (privacy isolation)
    accessible_docs = PermissionService.get_accessible_documents(user)
    available_owners = (
        accessible_docs
        .values_list('owner__username', flat=True)
        .distinct()
        .order_by('owner__username')
    )

    date_error = None
    try:
        documents_qs = DocumentService.search_and_filter_documents(
            user=user,
            query=search_query,
            category=category_filter,
            owner_username=owner_filter,
            date_from=date_from_raw or None,
            date_to=date_to_raw or None,
            sort_by=sort_by
        )
    except ValidationError as exc:
        date_error = exc.message
        messages.warning(request, f"Search filter notice: {exc.message}")
        documents_qs = Document.objects.none()

    paginator = Paginator(documents_qs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Preserve active filter parameters across pagination links
    query_params = request.GET.copy()
    if 'page' in query_params:
        del query_params['page']
    filter_querystring = query_params.urlencode()

    has_active_filters = bool(
        search_query or category_filter or owner_filter or
        date_from_raw or date_to_raw or (sort_by and sort_by != 'newest')
    )

    return render(request, 'documents/document_list.html', {
        'page_obj': page_obj,
        'categories': DocumentCategory.choices,
        'available_owners': available_owners,
        'selected_category': category_filter,
        'selected_owner': owner_filter,
        'date_from': date_from_raw,
        'date_to': date_to_raw,
        'sort_by': sort_by,
        'search_query': search_query,
        'total_count': documents_qs.count(),
        'filter_querystring': filter_querystring,
        'has_active_filters': has_active_filters,
        'date_error': date_error,
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
        'can_download': True,
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


@login_required
@require_http_methods(["GET", "HEAD"])
def document_download_view(request, doc_id):
    """
    Secure file delivery endpoint for confidential vault documents.
    Enforces centralized object-level authorization (READ permission).
    Streams file in chunks via Django FileResponse; never buffers entire file in RAM.
    Applies strict security headers: attachment disposition, nosniff, private no-store caching.
    """
    try:
        file_handle, document = DocumentService.get_authorized_file(
            actor=request.user,
            document_id=doc_id
        )
    except Document.DoesNotExist:
        raise Http404("Document not found.")
    except FileNotFoundError:
        logger.error(f"Missing storage file requested for document {doc_id} by user '{request.user.username}'.")
        raise Http404("Document storage file not found or unavailable.")
    except PermissionDenied as exc:
        try:
            from audit.services import AuditService
            target_doc = Document.objects.filter(pk=doc_id).first()
            if target_doc:
                AuditService.log_access_denied(
                    actor=request.user,
                    event_type='DOCUMENT_DOWNLOADED',
                    document=target_doc,
                    reason=str(exc),
                    request=request
                )
        except Exception as audit_err:
            logger.warning("Audit denial logging failed: %s", audit_err)
        raise exc

    # Record persistent audit event for authorized file download initiation
    from audit.services import AuditService
    AuditService.log_document_downloaded(
        actor=request.user,
        document=document,
        request=request
    )

    # Sanitize download filename for Content-Disposition header
    safe_filename = sanitize_filename(document.original_filename)
    if not safe_filename:
        safe_filename = f"document_{document.id}.bin"

    # Determine trusted content type (fallback to binary stream if unrecognized or missing)
    permitted_types = getattr(settings, 'PERMITTED_FILE_TYPES', {})
    if document.mime_type and document.mime_type in permitted_types:
        content_type = document.mime_type
    else:
        content_type = 'application/octet-stream'

    # Stream the file using FileResponse (chunk-based, auto-closes file handle)
    response = FileResponse(
        file_handle,
        as_attachment=True,
        filename=safe_filename,
        content_type=content_type
    )

    # Enforce strict caching and security headers
    response['Cache-Control'] = 'private, no-store, max-age=0, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['X-Content-Type-Options'] = 'nosniff'

    # Structured logging of authorized download event (no content, no tokens)
    logger.info(
        f"Authorized document download: User '{request.user.username}' (ID: {request.user.pk}) "
        f"downloaded document {document.pk} ('{document.name}', {document.formatted_size})."
    )

    return response


@login_required
def document_share_redirect_view(request, doc_id):
    """
    Convenience route redirecting to the centralized permission management view.
    """
    return redirect('permissions:manage', doc_id=doc_id)

