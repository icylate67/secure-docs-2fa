import base64
import io
import secrets
import string

import pyotp
import qrcode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect

from .models import MFASettings, SecurityLog


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


def log_security_event(request, user, event_type, details=''):
    SecurityLog.objects.create(
        user=user,
        event_type=event_type,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        details=details,
    )


def build_totp_qr(user, secret):
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email or user.username,
        issuer_name="2FA Portal"
    )

    qr = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return qr_code_base64, provisioning_uri


def generate_backup_codes(count=8, length=10):
    plain_codes = []
    hashed_codes = []

    alphabet = string.ascii_uppercase + string.digits

    for _ in range(count):
        code = ''.join(secrets.choice(alphabet) for _ in range(length))
        plain_codes.append(code)
        hashed_codes.append(make_password(code))

    return plain_codes, hashed_codes


@login_required
def security_settings_view(request):
    mfa_settings, _ = MFASettings.objects.get_or_create(user=request.user)
    profile = request.user.profile

    qr_code_base64 = None
    provisioning_uri = None
    new_backup_codes = None

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'start_totp':
            if not mfa_settings.totp_secret:
                mfa_settings.totp_secret = pyotp.random_base32()
                mfa_settings.save()

            qr_code_base64, provisioning_uri = build_totp_qr(
                request.user,
                mfa_settings.totp_secret
            )
            messages.info(request, 'Отсканируйте QR-код и введите код из приложения.')

        elif action == 'verify_totp':
            code = request.POST.get('totp_code', '').strip()

            if not mfa_settings.totp_secret:
                messages.error(request, 'Сначала нужно сгенерировать секретный ключ.')
                return redirect('security_settings')

            totp = pyotp.TOTP(mfa_settings.totp_secret)

            if totp.verify(code, valid_window=1):
                mfa_settings.is_totp_enabled = True
                mfa_settings.save()
                log_security_event(request, request.user, '2fa_enabled', 'Пользователь включил TOTP')
                messages.success(request, 'TOTP успешно включён.')
                return redirect('security_settings')
            else:
                messages.error(request, 'Неверный или устаревший код.')
                qr_code_base64, provisioning_uri = build_totp_qr(
                    request.user,
                    mfa_settings.totp_secret
                )

        elif action == 'disable_totp':
            mfa_settings.is_totp_enabled = False
            mfa_settings.totp_secret = ''
            mfa_settings.save()
            log_security_event(request, request.user, '2fa_disabled', 'Пользователь отключил TOTP')
            messages.warning(request, 'TOTP отключён.')
            return redirect('security_settings')

        elif action == 'enable_email':
            current_password = request.POST.get('current_password', '').strip()

            if not current_password or not request.user.check_password(current_password):
                messages.error(request, 'Для включения Email OTP необходимо ввести корректный текущий пароль.')
                return redirect('security_settings')

            if not request.user.email:
                messages.error(request, 'Для Email OTP у пользователя должен быть указан email.')
                return redirect('security_settings')

            if not profile.email_verified:
                messages.error(request, 'Email OTP можно включить только для подтверждённой электронной почты.')
                return redirect('security_settings')

            mfa_settings.is_email_enabled = True
            mfa_settings.save()
            log_security_event(request, request.user, '2fa_enabled', 'Пользователь включил Email OTP')
            messages.success(request, 'Email OTP успешно включён.')
            return redirect('security_settings')

        elif action == 'disable_email':
            current_password = request.POST.get('current_password', '').strip()

            if not current_password or not request.user.check_password(current_password):
                messages.error(request, 'Для отключения Email OTP необходимо ввести корректный текущий пароль.')
                return redirect('security_settings')

            mfa_settings.is_email_enabled = False
            mfa_settings.save()
            log_security_event(request, request.user, '2fa_disabled', 'Пользователь отключил Email OTP')
            messages.warning(request, 'Email OTP отключён.')
            return redirect('security_settings')

        elif action == 'generate_backup_codes':
            plain_codes, hashed_codes = generate_backup_codes()
            mfa_settings.backup_codes = hashed_codes
            mfa_settings.save()
            log_security_event(request, request.user, '2fa_enabled', 'Пользователь сгенерировал резервные коды')
            new_backup_codes = plain_codes
            messages.success(
                request,
                'Резервные коды успешно сгенерированы. Сохраните их в надёжном месте.'
            )

    if mfa_settings.totp_secret and not mfa_settings.is_totp_enabled:
        qr_code_base64, provisioning_uri = build_totp_qr(
            request.user,
            mfa_settings.totp_secret
        )

    return render(request, 'security/security_settings.html', {
        'mfa_settings': mfa_settings,
        'qr_code_base64': qr_code_base64,
        'provisioning_uri': provisioning_uri,
        'new_backup_codes': new_backup_codes,
        'profile_obj': profile,
    })


@login_required
def security_logs_view(request):
    logs = SecurityLog.objects.filter(user=request.user).order_by('-created_at')[:50]
    return render(request, 'security/security_logs.html', {'logs': logs})