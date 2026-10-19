"""
URL routing configuration for the TrustVault audit engine.
"""

from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.audit_trail_view, name='trail'),
    path('document/<int:doc_id>/', views.document_activity_view, name='document_activity'),
]
