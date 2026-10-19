from django.http import HttpResponse


def login_view(request):
    """Skeleton login endpoint (to be implemented in Phase 02)."""
    return HttpResponse("Phase 02: Login", status=200)


def logout_view(request):
    """Skeleton logout endpoint (to be implemented in Phase 02)."""
    return HttpResponse("Phase 02: Logout", status=200)


def register_view(request):
    """Skeleton registration endpoint (to be implemented in Phase 02)."""
    return HttpResponse("Phase 02: Register", status=200)


def user_list_view(request):
    """Skeleton user administration endpoint (to be implemented in Phase 02)."""
    return HttpResponse("Phase 02: User Administration", status=200)
