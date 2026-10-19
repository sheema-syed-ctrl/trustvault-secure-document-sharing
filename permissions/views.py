"""
Document sharing and permission management views for TrustVault.
Enforces owner-only access, server-side authorization, CSRF protection,
and cross-document IDOR defenses.
"""

import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_GET
from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib import messages
from documents.models import Document
from .models import DocumentPermission, PermissionType
from .services import PermissionService
from .forms import DocumentShareForm, DocumentPermissionUpdateForm

logger = logging.getLogger('trustvault')


@login_required
def document_share_manage_view(request, doc_id):
    """
    Primary interface for managing document permissions.
    Strictly restricted to the Document Owner.
    Displays active sharing permissions, recipient search, and grant form.
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization: strictly Document Owner
    if not PermissionService.can_manage_permissions(request.user, document):
        logger.warning(
            f"Unauthorized permission management access: User '{request.user.username}' (ID: {request.user.pk}, "
            f"Role: {request.user.role}) denied access to permissions for document {document.pk}."
        )
        raise PermissionDenied("Access denied: Only the document owner can manage permissions for this document.")

    search_query = request.GET.get('q', '').strip()

    if request.method == 'POST':
        form = DocumentShareForm(request.POST, document=document, actor=request.user)
        if form.is_valid():
            recipient = form.recipient_user
            permission_type = form.cleaned_data['permission_type']
            try:
                PermissionService.grant_permission(
                    actor=request.user,
                    document=document,
                    target_user=recipient,
                    permission_type=permission_type
                )
                messages.success(
                    request,
                    f"Successfully granted {permission_type} access to '{recipient.username}'."
                )
                return redirect('permissions:manage', doc_id=document.pk)
            except ValidationError as exc:
                form.add_error(None, exc)
            except PermissionDenied as exc:
                raise exc
    else:
        form = DocumentShareForm(document=document, actor=request.user)

    # Active permissions for this document
    active_permissions = DocumentPermission.objects.filter(
        document=document
    ).select_related('user', 'granted_by').order_by('-created_at')

    # Eligible shareable users (bounded, safe fields only)
    shareable_users = PermissionService.search_shareable_users(
        actor=request.user,
        document=document,
        query=search_query,
        limit=20
    )

    return render(request, 'permissions/share_manage.html', {
        'document': document,
        'permissions': active_permissions,
        'form': form,
        'shareable_users': shareable_users,
        'search_query': search_query,
        'permission_types': PermissionType.choices,
    })


@login_required
@require_POST
def document_permission_grant_view(request, doc_id):
    """
    POST-only endpoint to grant or update document access for a user.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if not PermissionService.can_manage_permissions(request.user, document):
        raise PermissionDenied("Access denied: Only the document owner can grant permissions for this document.")

    form = DocumentShareForm(request.POST, document=document, actor=request.user)
    if form.is_valid():
        recipient = form.recipient_user
        permission_type = form.cleaned_data['permission_type']
        PermissionService.grant_permission(
            actor=request.user,
            document=document,
            target_user=recipient,
            permission_type=permission_type
        )
        messages.success(
            request,
            f"Successfully granted {permission_type} access to '{recipient.username}'."
        )
        return redirect('permissions:manage', doc_id=document.pk)
    else:
        # Collect first error and flash as error message
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, error)
        return redirect('permissions:manage', doc_id=document.pk)


@login_required
@require_POST
def document_permission_update_view(request, doc_id, perm_id):
    """
    POST-only endpoint to modify an existing recipient's permission between READ and EDIT.
    Validates that perm_id belongs to doc_id to prevent cross-document IDOR attacks.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if not PermissionService.can_manage_permissions(request.user, document):
        raise PermissionDenied("Access denied: Only the document owner can modify permissions.")

    form = DocumentPermissionUpdateForm(request.POST)
    if not form.is_valid():
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, error)
        return redirect('permissions:manage', doc_id=document.pk)

    new_permission_type = form.cleaned_data['permission_type']

    try:
        perm = PermissionService.update_permission(
            actor=request.user,
            document=document,
            permission_id=perm_id,
            new_permission_type=new_permission_type
        )
        messages.success(
            request,
            f"Permission for '{perm.user.username}' updated to {perm.get_permission_type_display()}."
        )
    except ValidationError as exc:
        messages.error(request, str(exc))
    except PermissionDenied as exc:
        raise exc

    return redirect('permissions:manage', doc_id=document.pk)


@login_required
@require_POST
def document_permission_revoke_view(request, doc_id, perm_id):
    """
    POST-only endpoint to revoke a recipient's document permission.
    Validates that perm_id belongs to doc_id to prevent cross-document IDOR attacks.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if not PermissionService.can_manage_permissions(request.user, document):
        raise PermissionDenied("Access denied: Only the document owner can revoke permissions.")

    success = PermissionService.revoke_permission_by_id(
        actor=request.user,
        document=document,
        permission_id=perm_id
    )

    if success:
        messages.success(request, "Access has been successfully revoked for the recipient.")
    else:
        messages.info(request, "Permission was already revoked or not found.")

    return redirect('permissions:manage', doc_id=document.pk)


@login_required
@require_GET
def user_search_api_view(request, doc_id):
    """
    JSON endpoint for bounded recipient lookup.
    Strictly restricted to the Document Owner.
    Returns only safe account fields (id, username, role) for active non-owner accounts.
    """
    document = get_object_or_404(Document, pk=doc_id)

    if not PermissionService.can_manage_permissions(request.user, document):
        raise PermissionDenied("Access denied: Only the document owner can search recipients for this document.")

    query = request.GET.get('q', '').strip()
    users_qs = PermissionService.search_shareable_users(
        actor=request.user,
        document=document,
        query=query,
        limit=20
    )

    results = [
        {
            'id': u.pk,
            'username': u.username,
            'role': u.get_role_display(),
        }
        for u in users_qs
    ]

    return JsonResponse({'results': results})
