from django.http import HttpResponse


def index(request):
    """Skeleton dashboard endpoint (to be implemented in Phase 02/09)."""
    return HttpResponse("Phase 02/09: Dashboard", status=200)
