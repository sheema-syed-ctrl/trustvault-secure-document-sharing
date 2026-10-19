"""
Reusable authorization decorators for role-based view enforcement in TrustVault.
"""

from functools import wraps
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from .services import RBACService

User = get_user_model()


def role_required(allowed_roles):
    """
    Decorator to enforce that the authenticated user possesses one of the allowed roles.
    Raises PermissionDenied (HTTP 403) for authenticated users lacking authorization.
    Redirects unauthenticated users to LOGIN_URL.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')
            if request.user.is_superuser or request.user.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            raise PermissionDenied(
                f"Access denied: This operation requires one of the following roles: {', '.join(allowed_roles)}."
            )
        return _wrapped_view
    return decorator


def admin_required(view_func):
    """Restricts view access strictly to Platform Administrators."""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        if RBACService.is_admin(request.user):
            return view_func(request, *args, **kwargs)
        raise PermissionDenied("Access denied: Administrative privileges are required.")
    return _wrapped_view


def owner_required(view_func):
    """Restricts view access strictly to Document Owners."""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        if RBACService.is_owner(request.user) or request.user.is_superuser:
            return view_func(request, *args, **kwargs)
        raise PermissionDenied("Access denied: Document Owner role is required.")
    return _wrapped_view


def viewer_required(view_func):
    """Restricts view access to Viewers (or higher)."""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        if request.user.is_authenticated:
            return view_func(request, *args, **kwargs)
        raise PermissionDenied("Access denied: Valid authenticated user required.")
    return _wrapped_view
