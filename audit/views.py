"""
Views for TrustVault's persistent audit trail engine.
Provides:
  - Global Activity Monitoring Dashboard (strictly Administrator-only).
  - Document-Specific Activity Log (strictly Document Owner-only).
Enforces server-side authorization, bounded querysets, pagination, and safe output escaping.
"""

import logging
from datetime import datetime
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from accounts.services import RBACService
from documents.models import Document
from .models import AuditEvent, AuditEventType, AuditStatus
from .services import AuditService

logger = logging.getLogger('trustvault')


@login_required
@require_GET
def audit_trail_view(request):
    """
    Global Audit Activity Dashboard.
    Strictly restricted to users with Administrator privileges.
    Allows filtering by event type, actor username, date range, and general keyword.
    """
    if not RBACService.can_view_audit_logs(request.user):
        logger.warning(
            f"Unauthorized global audit trail access attempt: User '{request.user.username}' "
            f"(ID: {request.user.pk}, Role: {request.user.role}) denied."
        )
        raise PermissionDenied("Access denied: Only Administrators are authorized to view the global audit trail.")

    queryset = AuditEvent.objects.all().select_related('actor', 'target_document', 'target_user')

    # Filters
    event_type = request.GET.get('event_type', '').strip()
    actor_query = request.GET.get('actor', '').strip()
    search_q = request.GET.get('q', '').strip()
    date_from_str = request.GET.get('date_from', '').strip()
    date_to_str = request.GET.get('date_to', '').strip()

    if event_type and event_type in AuditEventType.values:
        queryset = queryset.filter(event_type=event_type)

    if actor_query:
        queryset = queryset.filter(actor_username__icontains=actor_query)

    if search_q:
        queryset = queryset.filter(
            Q(actor_username__icontains=search_q) |
            Q(target_document_name_snapshot__icontains=search_q) |
            Q(target_username__icontains=search_q) |
            Q(uuid__icontains=search_q)
        )

    if date_from_str:
        try:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d').date()
            queryset = queryset.filter(timestamp__date__gte=date_from)
        except ValueError:
            pass

    if date_to_str:
        try:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d').date()
            queryset = queryset.filter(timestamp__date__lte=date_to)
        except ValueError:
            pass

    queryset = queryset.order_by('-timestamp')

    # Pagination: 25 events per page
    paginator = Paginator(queryset, 25)
    page_number = request.GET.get('page', 1)
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    return render(request, 'audit/audit_trail.html', {
        'page_obj': page_obj,
        'event_types': AuditEventType.choices,
        'selected_event_type': event_type,
        'actor_query': actor_query,
        'search_q': search_q,
        'date_from': date_from_str,
        'date_to': date_to_str,
        'total_events_count': paginator.count,
    })


@login_required
@require_GET
def document_activity_view(request, doc_id):
    """
    Document-specific activity history.
    Strictly restricted to the authentic Document Owner.
    Displays all lifecycle events for the document (uploads, edits, downloads, sharing grants/revocations).
    """
    document = get_object_or_404(Document, pk=doc_id)

    # Server-side authorization check: strictly Document Owner
    if document.owner_id != request.user.pk:
        logger.warning(
            f"Unauthorized document activity inspection attempt: User '{request.user.username}' "
            f"(ID: {request.user.pk}, Role: {request.user.role}) denied access to document {document.pk}."
        )
        raise PermissionDenied("Access denied: Only the document owner can inspect activity for this document.")

    queryset = AuditService.get_document_audit_trail(request.user, document)

    paginator = Paginator(queryset, 20)
    page_number = request.GET.get('page', 1)
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    return render(request, 'audit/document_activity.html', {
        'document': document,
        'page_obj': page_obj,
        'total_events_count': paginator.count,
    })
