"""
Role-specific dashboard routing and views for TrustVault.
Enforces default-deny access, strict server-side authorization scoping,
bounded querysets, and distinct presentation by role:
  - Administrator: System governance, platform metrics, audit overview, and security denial alerts.
  - Document Owner: Personal repository metrics, category breakdown, active sharing overview,
                    recent document listing, and owner-scoped activity ledger.
  - Viewer: Strictly authorized document workspace, READ vs EDIT permission distinctions,
            and direct file access for granted documents.
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from accounts.models import User
from accounts.services import RBACService
from accounts.decorators import admin_required, owner_required
from documents.models import Document, DocumentCategory
from permissions.models import DocumentPermission, PermissionType
from permissions.services import PermissionService
from audit.models import AuditEvent, AuditEventType


@login_required
def index(request):
    """
    Central dashboard entry point.
    Dispatches to role-specific dashboard screens based on authenticated user's role.
    """
    user = request.user

    if user.is_admin_role:
        return admin_dashboard_view(request)
    elif user.is_owner_role:
        return owner_dashboard_view(request)
    else:
        return viewer_dashboard_view(request)


@admin_required
def admin_dashboard_view(request):
    """
    Administrator dashboard overview.
    Strictly restricted to users with Administrator privileges.
    Guarantees:
      - System-wide high-level operational metrics.
      - Bounded recent audit activity feed (safe metadata only).
      - Zero access to private document contents, bodies, or unauthorized downloads.
    """
    # System-wide user metrics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    inactive_users = User.objects.filter(is_active=False).count()
    admin_count = User.objects.filter(role=User.Role.ADMIN).count()
    owner_count = User.objects.filter(role=User.Role.OWNER).count()
    viewer_count = User.objects.filter(role=User.Role.VIEWER).count()

    # System-wide document & permission counts
    total_documents = Document.objects.count()
    total_permissions = DocumentPermission.objects.count()

    # Security denial metrics & recent violations
    security_denials_qs = AuditEvent.objects.filter(event_type=AuditEventType.SECURITY_ACCESS_DENIED)
    security_denial_count = security_denials_qs.count()
    recent_security_denials = security_denials_qs.select_related(
        'actor', 'target_document'
    ).order_by('-timestamp')[:5]

    # Recent general audit activity (bounded to 10 entries)
    recent_activity = AuditEvent.objects.select_related(
        'actor', 'target_document', 'target_user'
    ).order_by('-timestamp')[:10]

    # Recent users
    recent_users = User.objects.order_by('-date_joined')[:5]

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'admin_count': admin_count,
        'owner_count': owner_count,
        'viewer_count': viewer_count,
        'total_documents': total_documents,
        'total_permissions': total_permissions,
        'security_denial_count': security_denial_count,
        'recent_security_denials': recent_security_denials,
        'recent_activity': recent_activity,
        'recent_users': recent_users,
    }
    return render(request, 'dashboard/admin_dashboard.html', context)


@owner_required
def owner_dashboard_view(request):
    """
    Document Owner dashboard overview.
    Strictly restricted to authenticated Document Owners.
    Displays metrics and activities scoped strictly to documents owned by request.user.
    """
    user = request.user
    user_docs = Document.objects.filter(owner=user)
    total_documents = user_docs.count()

    # Active sharing metrics
    active_perms = DocumentPermission.objects.filter(document__owner=user)
    total_active_permissions = active_perms.count()
    read_permissions_count = active_perms.filter(permission_type=PermissionType.READ).count()
    edit_permissions_count = active_perms.filter(permission_type=PermissionType.EDIT).count()
    shared_documents_count = user_docs.filter(permissions__isnull=False).distinct().count()

    # Category breakdown via ORM aggregation
    cat_counts_qs = user_docs.values('category').annotate(count=Count('id'))
    cat_counts_map = {item['category']: item['count'] for item in cat_counts_qs}
    category_metrics = [
        {
            'code': code,
            'label': label,
            'count': cat_counts_map.get(code, 0)
        }
        for code, label in DocumentCategory.choices
    ]

    # Recently uploaded & updated documents
    recent_documents = user_docs.annotate(
        active_shares=Count('permissions')
    ).order_by('-created_at')[:5]
    recent_updated_documents = user_docs.order_by('-updated_at')[:5]

    # Owner-scoped recent activity: events touching owner's documents or performed by owner
    recent_activity = AuditEvent.objects.filter(
        Q(target_document__owner=user) |
        Q(actor=user, event_type__in=[
            AuditEventType.DOCUMENT_UPLOADED,
            AuditEventType.DOCUMENT_UPDATED,
            AuditEventType.DOCUMENT_DELETED,
            AuditEventType.PERMISSION_GRANTED,
            AuditEventType.PERMISSION_UPDATED,
            AuditEventType.PERMISSION_REVOKED,
        ])
    ).select_related('actor', 'target_user', 'target_document').order_by('-timestamp').distinct()[:10]

    context = {
        'total_documents': total_documents,
        'shared_count': shared_documents_count,
        'active_permissions': total_active_permissions,
        'read_permissions_count': read_permissions_count,
        'edit_permissions_count': edit_permissions_count,
        'category_metrics': category_metrics,
        'recent_documents': recent_documents,
        'recent_updated_documents': recent_updated_documents,
        'recent_activity': recent_activity,
    }
    return render(request, 'dashboard/owner_dashboard.html', context)


@login_required
def viewer_dashboard_view(request):
    """
    Viewer dashboard overview.
    Strictly restricted to documents explicitly authorized via PermissionService.
    Guarantees:
      - Only accessible documents are retrieved and displayed.
      - Explicit distinction between READ-only and EDIT-authorized documents.
      - Viewers with READ permission receive only view & download actions.
      - Viewers with EDIT permission receive edit metadata actions, but NEVER delete or share actions.
      - Revoked access is excluded immediately.
    """
    user = request.user
    accessible_docs = PermissionService.get_accessible_documents(user).select_related('owner')
    total_accessible = accessible_docs.count()

    # Get user permissions for accessible documents in a single query
    perms_qs = DocumentPermission.objects.filter(user=user, document__in=accessible_docs)
    user_perms_map = {p.document_id: p.permission_type for p in perms_qs}

    read_count = 0
    edit_count = 0
    recent_docs_list = []

    for doc in accessible_docs.order_by('-created_at'):
        if doc.owner_id == user.pk:
            perm_type = 'OWNER'
        else:
            perm_type = user_perms_map.get(doc.pk, PermissionType.READ)

        if perm_type == PermissionType.EDIT:
            edit_count += 1
        else:
            read_count += 1

        if len(recent_docs_list) < 8:
            doc.user_permission = perm_type
            recent_docs_list.append(doc)

    context = {
        'accessible_documents': recent_docs_list,
        'total_accessible': total_accessible,
        'read_count': read_count,
        'edit_count': edit_count,
    }
    return render(request, 'dashboard/viewer_dashboard.html', context)
