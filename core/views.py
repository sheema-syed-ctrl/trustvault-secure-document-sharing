"""
Core views and centralized HTTP error handlers for TrustVault.
Logs security-sensitive exceptions and renders clean, safe user responses.
"""

import logging
from django.shortcuts import render, redirect

logger = logging.getLogger('django.security')


def home_view(request):
    """Landing page redirecting authenticated users to dashboard or showcasing TrustVault."""
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    return render(request, 'core/home.html')


def bad_request_view(request, exception=None):
    """Handler for HTTP 400 Bad Request."""
    logger.warning(f"400 Bad Request on path: {request.path} | Client IP: {request.META.get('REMOTE_ADDR')}")
    return render(request, 'errors/400.html', status=400)


def permission_denied_view(request, exception=None):
    """Handler for HTTP 403 Forbidden / Access Denied."""
    user = request.user if request.user.is_authenticated else 'Anonymous'
    logger.warning(
        f"403 Forbidden on path: {request.path} | User: {user} | IP: {request.META.get('REMOTE_ADDR')}"
    )
    return render(request, 'errors/403.html', {'exception': exception}, status=403)


def not_found_view(request, exception=None):
    """Handler for HTTP 404 Not Found."""
    return render(request, 'errors/404.html', status=404)


def server_error_view(request):
    """Handler for HTTP 500 Internal Server Error."""
    logger.error(
        f"500 Internal Server Error on path: {request.path} | IP: {request.META.get('REMOTE_ADDR')}"
    )
    return render(request, 'errors/500.html', status=500)
