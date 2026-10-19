from django.urls import path
from . import views

app_name = 'documents'

urlpatterns = [
    path('', views.document_list_view, name='list'),
    path('upload/', views.document_upload_view, name='upload'),
    path('<int:doc_id>/', views.document_detail_view, name='detail'),
    path('<int:doc_id>/download/', views.document_download_view, name='download'),
    path('<int:doc_id>/edit/', views.document_edit_view, name='edit'),
    path('<int:doc_id>/delete/', views.document_delete_view, name='delete'),
]
