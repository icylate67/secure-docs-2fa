from django.urls import path
from .views import (
    register_view,
    verify_email_registration_view,
    change_email_view,
    confirm_email_change_view,
    login_view,
    select_2fa_method_view,
    back_to_2fa_selection_view,
    verify_totp_view,
    verify_email_view,
    verify_backup_code_view,
    dashboard_view,
    profile_edit_view,
    delete_avatar_view,
    change_password_view,
    delete_account_view,
    delete_account_verify_2fa_view,
    admin_users_view,
    admin_security_logs_view,
    admin_documents_view,
    logout_view,
)

urlpatterns = [
    path('register/', register_view, name='register'),
    path('verify-email-registration/<str:token>/', verify_email_registration_view, name='verify_email_registration'),
    path('change-email/', change_email_view, name='change_email'),
    path('confirm-email-change/<str:token>/', confirm_email_change_view, name='confirm_email_change'),

    path('login/', login_view, name='login'),
    path('select-2fa-method/', select_2fa_method_view, name='select_2fa_method'),
    path('back-to-2fa-selection/', back_to_2fa_selection_view, name='back_to_2fa_selection'),
    path('verify-totp/', verify_totp_view, name='verify_totp'),
    path('verify-email/', verify_email_view, name='verify_email'),
    path('verify-backup-code/', verify_backup_code_view, name='verify_backup_code'),

    path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/edit/', profile_edit_view, name='profile_edit'),
    path('profile/delete-avatar/', delete_avatar_view, name='delete_avatar'),
    path('profile/change-password/', change_password_view, name='change_password'),
    path('profile/delete-account/', delete_account_view, name='delete_account'),
    path('profile/delete-account/verify-2fa/', delete_account_verify_2fa_view, name='delete_account_verify_2fa'),

    path('admin-panel/users/', admin_users_view, name='admin_users'),
    path('admin-panel/logs/', admin_security_logs_view, name='admin_security_logs'),
    path('admin-panel/documents/', admin_documents_view, name='admin_documents'),

    path('logout/', logout_view, name='logout'),
]