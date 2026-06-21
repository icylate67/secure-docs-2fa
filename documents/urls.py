from django.urls import path
from .views import document_list_view, document_download_view, document_delete_view

urlpatterns = [
    path('documents/', document_list_view, name='documents'),
    path('documents/<int:document_id>/download/', document_download_view, name='document_download'),
    path('documents/<int:document_id>/delete/', document_delete_view, name='document_delete'),
]