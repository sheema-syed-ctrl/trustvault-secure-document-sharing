"""
URL Configuration for TrustVault project.
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('documents/', include('documents.urls', namespace='documents')),
    path('permissions/', include('permissions.urls', namespace='permissions')),
    path('audit/', include('audit.urls', namespace='audit')),
    path('dashboard/', include('dashboard.urls', namespace='dashboard')),
    path('', include('core.urls', namespace='core')),
]

# Centralized custom error handlers
handler400 = 'core.views.bad_request_view'
handler403 = 'core.views.permission_denied_view'
handler404 = 'core.views.not_found_view'
handler500 = 'core.views.server_error_view'
