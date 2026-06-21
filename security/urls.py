from django.urls import path
from .views import security_settings_view, security_logs_view

urlpatterns = [
    path('security/settings/', security_settings_view, name='security_settings'),
    path('security/logs/', security_logs_view, name='security_logs'),
]