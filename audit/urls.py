from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.audit_trail_view, name='trail'),
]
