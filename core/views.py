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


def health_check_view(request):
    """
    Production health check probe for load balancers and container orchestrators.
    Verifies:
      - Database connectivity via active cursor query.
      - Protected private storage directory accessibility and writeability.
    Returns HTTP 200 with JSON payload when all systems pass, or 503 when degraded.
    """
    import uuid
    from pathlib import Path
    from django.conf import settings
    from django.db import connection
    from django.http import JsonResponse

    # 1. Probe database
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1;")
            cursor.fetchone()
        db_ok = True
        db_status = "connected"
    except Exception as exc:
        db_ok = False
        db_status = f"disconnected: {exc}"
        logger.error(f"Health check database probe failed: {exc}")

    # 2. Probe private storage
    try:
        root = Path(settings.PROTECTED_MEDIA_ROOT).resolve()
        if root.exists() and root.is_dir():
            probe_path = root / f".health_{uuid.uuid4().hex}.tmp"
            probe_path.write_text("health probe", encoding="utf-8")
            if probe_path.exists():
                probe_path.unlink(missing_ok=True)
            storage_ok = True
            storage_status = "accessible"
        else:
            storage_ok = False
            storage_status = "missing_directory"
    except Exception as exc:
        storage_ok = False
        storage_status = f"error: {exc}"
        logger.error(f"Health check storage probe failed: {exc}")

    is_healthy = db_ok and storage_ok
    status_code = 200 if is_healthy else 503

    return JsonResponse(
        {
            "status": "healthy" if is_healthy else "unhealthy",
            "database": db_status,
            "storage": storage_status,
            "version": "1.0.0",
        },
        status=status_code
    )
