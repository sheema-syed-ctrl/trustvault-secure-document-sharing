from django.http import HttpResponse


def document_list(request):
    """Skeleton document listing endpoint (to be implemented in Phase 03)."""
    return HttpResponse("Phase 03: Document List", status=200)


def document_upload(request):
    """Skeleton document upload endpoint (to be implemented in Phase 03)."""
    return HttpResponse("Phase 03: Document Upload", status=200)
