"""
Role-specific dashboard routing and views for TrustVault.
Enforces default-deny access and distinct presentation by role:
  - Administrator: User management & audit oversight overview.
  - Document Owner: Personal document repository & upload overview.
  - Viewer: Documents explicitly shared with the user.
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from accounts.models import User


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


@login_required
def admin_dashboard_view(request):
    """Administrator dashboard overview."""
    context = {
        'total_users': User.objects.count(),
        'admin_count': User.objects.filter(role=User.Role.ADMIN).count(),
        'owner_count': User.objects.filter(role=User.Role.OWNER).count(),
        'viewer_count': User.objects.filter(role=User.Role.VIEWER).count(),
        'recent_users': User.objects.order_by('-date_joined')[:5],
    }
    return render(request, 'dashboard/admin_dashboard.html', context)


from documents.models import Document


@login_required
def owner_dashboard_view(request):
    """Document Owner dashboard overview."""
    user_docs = Document.objects.filter(owner=request.user)
    context = {
        'recent_documents': user_docs.order_by('-created_at')[:5],
        'total_documents': user_docs.count(),
        'shared_count': 0,
    }
    return render(request, 'dashboard/owner_dashboard.html', context)


@login_required
def viewer_dashboard_view(request):
    """Viewer dashboard overview."""
    context = {
        'accessible_documents': [],  # Integrated with DocumentPermission in Phase 04
        'total_accessible': 0,
    }
    return render(request, 'dashboard/viewer_dashboard.html', context)
