from django.urls import path
from . import views

app_name = 'permissions'

urlpatterns = [
    path('document/<int:doc_id>/', views.document_share_manage_view, name='manage'),
    path('document/<int:doc_id>/grant/', views.document_permission_grant_view, name='grant'),
    path('document/<int:doc_id>/update/<int:perm_id>/', views.document_permission_update_view, name='update'),
    path('document/<int:doc_id>/revoke/<int:perm_id>/', views.document_permission_revoke_view, name='revoke'),
    path('document/<int:doc_id>/users/search/', views.user_search_api_view, name='user_search'),
]
