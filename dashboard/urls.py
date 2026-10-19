from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('admin/', views.admin_dashboard_view, name='admin'),
    path('owner/', views.owner_dashboard_view, name='owner'),
    path('viewer/', views.viewer_dashboard_view, name='viewer'),
]
