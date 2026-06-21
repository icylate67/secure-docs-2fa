from django.db import models
from django.contrib.auth.models import User


class MFASettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa_settings')
    is_totp_enabled = models.BooleanField(default=False)
    is_email_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=255, blank=True, null=True)
    backup_codes = models.JSONField(default=list, blank=True)
    failed_2fa_attempts = models.PositiveIntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'MFA settings: {self.user.username}'


class EmailOTPCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_otp_codes')
    code_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f'Email OTP for {self.user.username}'


class SecurityLog(models.Model):
    EVENT_CHOICES = [
        ('login_success', 'Успешный вход'),
        ('login_failed', 'Неуспешный вход'),
        ('2fa_success', 'Успешная 2FA'),
        ('2fa_failed', 'Неуспешная 2FA'),
        ('2fa_enabled', '2FA включена'),
        ('2fa_disabled', '2FA отключена'),
        ('recovery_code_used', 'Использован резервный код'),
        ('lockout', 'Временная блокировка'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='security_logs')
    event_type = models.CharField(max_length=50, choices=EVENT_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.event_type} - {self.created_at}'