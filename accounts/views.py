import pyotp
import secrets
import string

from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone

from .forms import RegisterForm, LoginForm, ProfileUpdateForm, EmailChangeForm
from .models import UserProfile
from documents.models import Document
from security.models import MFASettings, SecurityLog, EmailOTPCode


signer = TimestampSigner()

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 5


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


def is_admin_user(user):
    return user.is_authenticated and (
        user.is_staff or (
            hasattr(user, 'profile') and user.profile.role == 'admin'
        )
    )


def get_login_lock_data(request):
    failed_attempts = request.session.get('login_failed_attempts', 0)
    lockout_until_str = request.session.get('login_lockout_until')

    lockout_until = None
    if lockout_until_str:
        try:
            lockout_until = timezone.datetime.fromisoformat(lockout_until_str)
            if timezone.is_naive(lockout_until):
                lockout_until = timezone.make_aware(lockout_until, timezone.get_current_timezone())
        except ValueError:
            lockout_until = None

    return failed_attempts, lockout_until


def reset_login_attempts(request):
    request.session['login_failed_attempts'] = 0
    request.session['login_lockout_until'] = None


def register_failed_login_attempt(request):
    failed_attempts, _ = get_login_lock_data(request)
    failed_attempts += 1

    request.session['login_failed_attempts'] = failed_attempts

    if failed_attempts >= LOGIN_MAX_ATTEMPTS:
        lockout_until = timezone.now() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        request.session['login_lockout_until'] = lockout_until.isoformat()
        request.session['login_failed_attempts'] = 0
        return lockout_until

    return None


def is_login_locked(request):
    _, lockout_until = get_login_lock_data(request)

    if lockout_until and timezone.now() < lockout_until:
        return True, lockout_until

    if lockout_until and timezone.now() >= lockout_until:
        reset_login_attempts(request)

    return False, None


def is_2fa_locked(mfa_settings):
    if mfa_settings.lockout_until and timezone.now() < mfa_settings.lockout_until:
        return True
    return False


def register_failed_2fa_attempt(mfa_settings):
    mfa_settings.failed_2fa_attempts += 1

    if mfa_settings.failed_2fa_attempts >= 5:
        mfa_settings.lockout_until = timezone.now() + timedelta(minutes=5)
        mfa_settings.failed_2fa_attempts = 0

    mfa_settings.save()


def reset_2fa_attempts(mfa_settings):
    mfa_settings.failed_2fa_attempts = 0
    mfa_settings.lockout_until = None
    mfa_settings.save()


def generate_email_otp(user):
    code = ''.join(secrets.choice(string.digits) for _ in range(6))

    EmailOTPCode.objects.filter(user=user, is_used=False).update(is_used=True)

    EmailOTPCode.objects.create(
        user=user,
        code_hash=make_password(code),
        expires_at=timezone.now() + timedelta(minutes=5),
        is_used=False,
    )

    send_mail(
        subject='Код подтверждения входа',
        message=f'Ваш одноразовый код для входа: {code}\nСрок действия: 5 минут.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )


def send_verification_email(request, user):
    token = signer.sign(user.id)
    verify_path = reverse('verify_email_registration', args=[token])
    verify_url = request.build_absolute_uri(verify_path)

    send_mail(
        subject='Подтверждение электронной почты',
        message=(
            f'Здравствуйте, {user.username}!\n\n'
            f'Для подтверждения электронной почты перейдите по ссылке:\n{verify_url}\n\n'
            f'Ссылка действует ограниченное время.'
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )


def send_email_change_verification(request, user, new_email):
    token = signer.sign(f'{user.id}:{new_email}')
    verify_path = reverse('confirm_email_change', args=[token])
    verify_url = request.build_absolute_uri(verify_path)

    send_mail(
        subject='Подтверждение смены электронной почты',
        message=(
            f'Здравствуйте, {user.username}!\n\n'
            f'Для подтверждения новой электронной почты перейдите по ссылке:\n{verify_url}\n\n'
            f'Если вы не запрашивали смену email, проигнорируйте это письмо.'
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[new_email],
        fail_silently=False,
    )


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data['email']
            user.is_active = False
            user.save()

            profile = user.profile
            profile.email_verified = False
            profile.pending_email = ''
            profile.save()

            send_verification_email(request, user)

            messages.success(
                request,
                'Регистрация прошла успешно. На вашу почту отправлена ссылка для подтверждения email.'
            )
            return redirect('login')
        else:
            messages.error(request, 'Не удалось зарегистрировать пользователя. Проверьте поля формы.')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def verify_email_registration_view(request, token):
    try:
        user_id = signer.unsign(token, max_age=60 * 60 * 24)
        user = User.objects.get(id=user_id)
        profile, _ = UserProfile.objects.get_or_create(user=user)

        if profile.email_verified and user.is_active:
            messages.info(request, 'Электронная почта уже была подтверждена.')
            return redirect('login')

        profile.email_verified = True
        profile.save()

        user.is_active = True
        user.save(update_fields=['is_active'])

        messages.success(request, 'Электронная почта успешно подтверждена. Теперь вы можете войти в систему.')
        return redirect('login')

    except SignatureExpired:
        messages.error(request, 'Срок действия ссылки подтверждения истёк.')
        return redirect('login')
    except (BadSignature, User.DoesNotExist):
        messages.error(request, 'Ссылка подтверждения недействительна.')
        return redirect('login')


@login_required
def change_email_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = EmailChangeForm(request.user, request.POST)
        if form.is_valid():
            new_email = form.cleaned_data['new_email'].strip().lower()

            profile.pending_email = new_email
            profile.email_verified = False
            profile.save()

            send_email_change_verification(request, request.user, new_email)

            log_security_event(
                request,
                request.user,
                'profile_updated',
                f'Запрошена смена email на {new_email}'
            )
            messages.success(
                request,
                'На новый email отправлена ссылка подтверждения. Почта будет изменена только после перехода по ссылке.'
            )
            return redirect('profile_edit')
        else:
            messages.error(request, 'Не удалось отправить подтверждение смены email. Проверьте данные.')
    else:
        form = EmailChangeForm(request.user)

    return render(request, 'accounts/change_email.html', {
        'form': form,
        'current_email': request.user.email,
        'pending_email': profile.pending_email,
    })


def confirm_email_change_view(request, token):
    try:
        raw_value = signer.unsign(token, max_age=60 * 60 * 24)
        user_id, new_email = raw_value.split(':', 1)

        user = User.objects.get(id=user_id)
        profile, _ = UserProfile.objects.get_or_create(user=user)

        if not profile.pending_email or profile.pending_email.lower() != new_email.lower():
            messages.error(request, 'Запрос на смену email не найден или уже обработан.')
            return redirect('login')

        user.email = new_email
        user.save()

        profile.pending_email = ''
        profile.email_verified = True
        profile.save()

        messages.success(request, 'Электронная почта успешно обновлена и подтверждена.')
        return redirect('login')

    except SignatureExpired:
        messages.error(request, 'Срок действия ссылки подтверждения смены email истёк.')
        return redirect('login')
    except (BadSignature, User.DoesNotExist, ValueError):
        messages.error(request, 'Ссылка подтверждения недействительна.')
        return redirect('login')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    locked, lockout_until = is_login_locked(request)
    if locked:
        seconds_left = int((lockout_until - timezone.now()).total_seconds())
        minutes_left = max(1, seconds_left // 60)
        messages.error(request, f'Слишком много неудачных попыток входа. Повторите через {minutes_left} мин.')
        return render(request, 'accounts/login.html', {'form': LoginForm()})

    form = LoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            reset_login_attempts(request)

            mfa_settings, _ = MFASettings.objects.get_or_create(user=user)

            if mfa_settings.is_totp_enabled or mfa_settings.is_email_enabled or mfa_settings.backup_codes:
                request.session['pre_2fa_user_id'] = user.id
                request.session['pre_2fa_method'] = None
                log_security_event(request, user, 'login_success', 'Пароль подтверждён, ожидается выбор второго фактора')
                return redirect('select_2fa_method')
            else:
                login(request, user)
                log_security_event(request, user, 'login_success', 'Вход без 2FA')
                messages.success(request, 'Вы успешно вошли в систему.')
                return redirect('dashboard')

        inactive_user = User.objects.filter(username=username).first()

        if inactive_user and inactive_user.check_password(password) and not inactive_user.is_active:
            log_security_event(request, inactive_user, 'login_failed', 'Попытка входа до подтверждения email')
            messages.warning(
                request,
                'Аккаунт ещё не подтверждён. Проверьте электронную почту и перейдите по ссылке из письма.'
            )
            return render(request, 'accounts/login.html', {'form': form})

        lockout_until = register_failed_login_attempt(request)
        log_security_event(request, None, 'login_failed', 'Неверный логин или пароль')

        if lockout_until:
            messages.error(request, 'Слишком много неверных попыток. Вход временно заблокирован.')
        else:
            messages.error(request, 'Неверный логин или пароль.')

    return render(request, 'accounts/login.html', {'form': form})


def select_2fa_method_view(request):
    pre_2fa_user_id = request.session.get('pre_2fa_user_id')

    if not pre_2fa_user_id:
        return redirect('login')

    try:
        user = User.objects.get(id=pre_2fa_user_id)
        mfa_settings, _ = MFASettings.objects.get_or_create(user=user)
    except User.DoesNotExist:
        request.session.pop('pre_2fa_user_id', None)
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'Не удалось выбрать метод двухфакторной аутентификации.')
        return redirect('login')

    is_totp_available = bool(
        mfa_settings.is_totp_enabled and
        mfa_settings.totp_secret and
        str(mfa_settings.totp_secret).strip()
    )

    is_email_available = bool(
        mfa_settings.is_email_enabled and
        user.email and
        str(user.email).strip()
    )

    has_backup_codes = bool(mfa_settings.backup_codes)

    available_methods = []

    if is_totp_available:
        available_methods.append('totp')

    if is_email_available:
        available_methods.append('email')

    if has_backup_codes:
        available_methods.append('backup')

    if not available_methods:
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'Для пользователя не настроен ни один рабочий второй фактор.')
        return redirect('login')

    if len(available_methods) == 1:
        only_method = available_methods[0]
        request.session['pre_2fa_method'] = only_method

        if only_method == 'totp':
            return redirect('verify_totp')

        if only_method == 'email':
            generate_email_otp(user)
            return redirect('verify_email')

        if only_method == 'backup':
            return redirect('verify_backup_code')

    if request.method == 'POST':
        method = request.POST.get('method')

        if method == 'totp' and is_totp_available:
            request.session['pre_2fa_method'] = 'totp'
            return redirect('verify_totp')

        if method == 'email' and is_email_available:
            request.session['pre_2fa_method'] = 'email'
            generate_email_otp(user)
            return redirect('verify_email')

        if method == 'backup' and has_backup_codes:
            request.session['pre_2fa_method'] = 'backup'
            return redirect('verify_backup_code')

        messages.error(request, 'Выбран недоступный метод подтверждения.')
        return redirect('select_2fa_method')

    return render(request, 'accounts/select_2fa_method.html', {
        'user_obj': user,
        'is_totp_available': is_totp_available,
        'is_email_available': is_email_available,
        'has_backup_codes': has_backup_codes,
    })

def back_to_2fa_selection_view(request):
    pre_2fa_user_id = request.session.get('pre_2fa_user_id')

    if not pre_2fa_user_id:
        return redirect('login')

    request.session['pre_2fa_method'] = None
    messages.info(request, 'Выберите другой способ подтверждения входа.')
    return redirect('select_2fa_method')


def verify_totp_view(request):
    pre_2fa_user_id = request.session.get('pre_2fa_user_id')

    if not pre_2fa_user_id:
        return redirect('login')

    try:
        user = User.objects.get(id=pre_2fa_user_id)
        mfa_settings, _ = MFASettings.objects.get_or_create(user=user)
    except User.DoesNotExist:
        request.session.pop('pre_2fa_user_id', None)
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'Не удалось завершить двухфакторную аутентификацию.')
        return redirect('login')

    # Если TOTP реально не настроен — не пускаем
    if not mfa_settings.is_totp_enabled or not mfa_settings.totp_secret or not str(mfa_settings.totp_secret).strip():
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'TOTP не настроен для данного пользователя.')
        return redirect('select_2fa_method')

    # Фиксируем выбранный метод
    request.session['pre_2fa_method'] = 'totp'

    if is_2fa_locked(mfa_settings):
        seconds_left = int((mfa_settings.lockout_until - timezone.now()).total_seconds())
        minutes_left = max(1, seconds_left // 60)
        messages.error(request, f'Слишком много неудачных попыток. Повторите через {minutes_left} мин.')
        return render(request, 'accounts/verify_totp.html', {'user_obj': user})

    if request.method == 'POST':
        code = request.POST.get('totp_code', '').strip()

        totp = pyotp.TOTP(mfa_settings.totp_secret)

        if totp.verify(code, valid_window=1):
            reset_2fa_attempts(mfa_settings)

            request.session.pop('pre_2fa_user_id', None)
            request.session.pop('pre_2fa_method', None)

            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            log_security_event(request, user, '2fa_success', 'TOTP успешно подтверждён')
            messages.success(request, 'Двухфакторная аутентификация успешно пройдена.')
            return redirect('dashboard')
        else:
            register_failed_2fa_attempt(mfa_settings)

            if mfa_settings.lockout_until:
                log_security_event(request, user, 'lockout', 'Блокировка после неудачных попыток TOTP')
                messages.error(request, 'Слишком много неверных попыток. Ввод кода временно заблокирован.')
            else:
                log_security_event(request, user, '2fa_failed', 'Неверный TOTP код')
                messages.error(request, 'Неверный или устаревший код.')

    return render(request, 'accounts/verify_totp.html', {'user_obj': user})


def verify_email_view(request):
    pre_2fa_user_id = request.session.get('pre_2fa_user_id')
    pre_2fa_method = request.session.get('pre_2fa_method')

    if not pre_2fa_user_id or pre_2fa_method != 'email':
        return redirect('login')

    try:
        user = User.objects.get(id=pre_2fa_user_id)
        mfa_settings = MFASettings.objects.get(user=user)
    except (User.DoesNotExist, MFASettings.DoesNotExist):
        request.session.pop('pre_2fa_user_id', None)
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'Пользователь не найден.')
        return redirect('login')

    if is_2fa_locked(mfa_settings):
        seconds_left = int((mfa_settings.lockout_until - timezone.now()).total_seconds())
        minutes_left = max(1, seconds_left // 60)
        messages.error(request, f'Слишком много неудачных попыток. Повторите через {minutes_left} мин.')
        return render(request, 'accounts/verify_email.html', {'user_obj': user})

    if request.method == 'POST':
        action = request.POST.get('action', 'verify')

        if action == 'resend':
            generate_email_otp(user)
            messages.info(request, 'Новый код отправлен на электронную почту.')
            return redirect('verify_email')

        code = request.POST.get('email_code', '').strip()

        otp_obj = EmailOTPCode.objects.filter(
            user=user,
            is_used=False
        ).order_by('-created_at').first()

        if not otp_obj:
            messages.error(request, 'Активный код не найден. Запросите новый.')
            return redirect('verify_email')

        if timezone.now() > otp_obj.expires_at:
            otp_obj.is_used = True
            otp_obj.save()
            log_security_event(request, user, '2fa_failed', 'Email OTP просрочен')
            messages.error(request, 'Срок действия кода истёк. Запросите новый.')
            return redirect('verify_email')

        if check_password(code, otp_obj.code_hash):
            otp_obj.is_used = True
            otp_obj.save()

            reset_2fa_attempts(mfa_settings)

            request.session.pop('pre_2fa_user_id', None)
            request.session.pop('pre_2fa_method', None)

            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            log_security_event(request, user, '2fa_success', 'Email OTP успешно подтверждён')
            messages.success(request, 'Двухфакторная аутентификация успешно пройдена.')
            return redirect('dashboard')
        else:
            register_failed_2fa_attempt(mfa_settings)

            if mfa_settings.lockout_until:
                log_security_event(request, user, 'lockout', 'Блокировка после неудачных попыток Email OTP')
                messages.error(request, 'Слишком много неверных попыток. Ввод кода временно заблокирован.')
            else:
                log_security_event(request, user, '2fa_failed', 'Неверный Email OTP код')
                messages.error(request, 'Неверный код подтверждения.')

    return render(request, 'accounts/verify_email.html', {'user_obj': user})


def verify_backup_code_view(request):
    pre_2fa_user_id = request.session.get('pre_2fa_user_id')
    pre_2fa_method = request.session.get('pre_2fa_method')

    if not pre_2fa_user_id or pre_2fa_method != 'backup':
        return redirect('login')

    try:
        user = User.objects.get(id=pre_2fa_user_id)
        mfa_settings = MFASettings.objects.get(user=user)
    except (User.DoesNotExist, MFASettings.DoesNotExist):
        request.session.pop('pre_2fa_user_id', None)
        request.session.pop('pre_2fa_method', None)
        messages.error(request, 'Не удалось завершить двухфакторную аутентификацию.')
        return redirect('login')

    if request.method == 'POST':
        backup_code = request.POST.get('backup_code', '').strip()

        matched_hash = None
        for saved_hash in mfa_settings.backup_codes:
            if check_password(backup_code, saved_hash):
                matched_hash = saved_hash
                break

        if matched_hash:
            mfa_settings.backup_codes.remove(matched_hash)
            mfa_settings.save()
            reset_2fa_attempts(mfa_settings)

            request.session.pop('pre_2fa_user_id', None)
            request.session.pop('pre_2fa_method', None)

            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            log_security_event(request, user, '2fa_success', 'Вход выполнен по резервному коду')
            messages.success(request, 'Вход выполнен с использованием резервного кода.')
            return redirect('dashboard')
        else:
            log_security_event(request, user, '2fa_failed', 'Неверный резервный код')
            messages.error(request, 'Неверный резервный код.')

    return render(request, 'accounts/verify_backup_code.html', {'user_obj': user})


@login_required
def dashboard_view(request):
    mfa_settings, _ = MFASettings.objects.get_or_create(user=request.user)

    documents_count = Document.objects.filter(owner=request.user).count()
    confidential_count = Document.objects.filter(owner=request.user, is_confidential=True).count()
    recent_logs = SecurityLog.objects.filter(user=request.user).order_by('-created_at')[:5]

    context = {
        'mfa_settings': mfa_settings,
        'documents_count': documents_count,
        'confidential_count': confidential_count,
        'recent_logs': recent_logs,
    }
    return render(request, 'accounts/dashboard.html', context)


@login_required
def profile_edit_view(request):
    mfa_settings, _ = MFASettings.objects.get_or_create(user=request.user)
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Профиль успешно обновлён.')
            return redirect('profile_edit')
        else:
            messages.error(request, 'Не удалось обновить профиль. Проверьте введённые данные.')
    else:
        form = ProfileUpdateForm(instance=request.user)

    return render(request, 'accounts/profile_edit.html', {
        'form': form,
        'mfa_settings': mfa_settings,
        'profile_obj': profile,
    })


@login_required
def delete_avatar_view(request):
    if request.method == 'POST':
        profile = request.user.profile

        if profile.avatar:
            profile.avatar.delete(save=False)
            profile.avatar = None
            profile.save()

            request.user.refresh_from_db()
            messages.success(request, 'Аватар успешно удалён.')
        else:
            messages.info(request, 'У пользователя нет загруженного аватара.')

    return redirect('profile_edit')


@login_required
def delete_account_view(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '').strip()

        if not request.user.check_password(current_password):
            messages.error(request, 'Неверный текущий пароль.')
            return redirect('delete_account')

        mfa_settings, _ = MFASettings.objects.get_or_create(user=request.user)

        if mfa_settings.is_totp_enabled or mfa_settings.is_email_enabled:
            request.session['delete_account_pending'] = True

            if mfa_settings.is_totp_enabled:
                request.session['delete_account_2fa_method'] = 'totp'
            elif mfa_settings.is_email_enabled:
                request.session['delete_account_2fa_method'] = 'email'
                generate_email_otp(request.user)

            messages.info(request, 'Подтвердите удаление аккаунта с помощью второго фактора.')
            return redirect('delete_account_verify_2fa')

        user = request.user

        if hasattr(user, 'profile') and user.profile.avatar:
            user.profile.avatar.delete(save=False)

        for document in user.documents.all():
            if document.file:
                document.file.delete(save=False)

        logout(request)
        user.delete()

        messages.success(request, 'Аккаунт успешно удалён.')
        return redirect('login')

    return render(request, 'accounts/delete_account.html')


@login_required
def delete_account_verify_2fa_view(request):
    if not request.session.get('delete_account_pending'):
        return redirect('delete_account')

    method = request.session.get('delete_account_2fa_method')
    mfa_settings, _ = MFASettings.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        if method == 'totp':
            code = request.POST.get('totp_code', '').strip()

            if not mfa_settings.totp_secret:
                messages.error(request, 'Секрет TOTP не найден.')
                return redirect('delete_account')

            totp = pyotp.TOTP(mfa_settings.totp_secret)

            if not totp.verify(code, valid_window=1):
                messages.error(request, 'Неверный или устаревший TOTP-код.')
                return redirect('delete_account_verify_2fa')

        elif method == 'email':
            action = request.POST.get('action', 'verify')

            if action == 'resend':
                generate_email_otp(request.user)
                messages.info(request, 'Новый код отправлен на электронную почту.')
                return redirect('delete_account_verify_2fa')

            code = request.POST.get('email_code', '').strip()

            otp_obj = EmailOTPCode.objects.filter(
                user=request.user,
                is_used=False
            ).order_by('-created_at').first()

            if not otp_obj:
                messages.error(request, 'Активный код не найден. Запросите новый.')
                return redirect('delete_account_verify_2fa')

            if timezone.now() > otp_obj.expires_at:
                otp_obj.is_used = True
                otp_obj.save()
                messages.error(request, 'Срок действия кода истёк. Запросите новый.')
                return redirect('delete_account_verify_2fa')

            if not check_password(code, otp_obj.code_hash):
                messages.error(request, 'Неверный Email OTP код.')
                return redirect('delete_account_verify_2fa')

            otp_obj.is_used = True
            otp_obj.save()

        else:
            messages.error(request, 'Метод подтверждения не определён.')
            return redirect('delete_account')

        user = request.user

        if hasattr(user, 'profile') and user.profile.avatar:
            user.profile.avatar.delete(save=False)

        for document in user.documents.all():
            if document.file:
                document.file.delete(save=False)

        request.session.pop('delete_account_pending', None)
        request.session.pop('delete_account_2fa_method', None)

        logout(request)
        user.delete()

        messages.success(request, 'Аккаунт успешно удалён после подтверждения второго фактора.')
        return redirect('login')

    return render(request, 'accounts/delete_account_verify_2fa.html', {
        'method': method,
    })


@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Пароль успешно изменён.')
            return redirect('profile_edit')
        else:
            messages.error(request, 'Не удалось изменить пароль. Проверьте введённые данные.')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'accounts/change_password.html', {
        'form': form,
    })


@user_passes_test(is_admin_user)
def admin_users_view(request):
    users = User.objects.select_related('profile').filter(is_active=True).order_by('-date_joined')

    return render(request, 'accounts/admin_users.html', {
        'users_list': users,
    })


@user_passes_test(is_admin_user)
def admin_security_logs_view(request):
    logs = SecurityLog.objects.select_related('user').order_by('-created_at')[:200]

    return render(request, 'accounts/admin_security_logs.html', {
        'logs': logs,
    })


@user_passes_test(is_admin_user)
def admin_documents_view(request):
    query = request.GET.get('q', '').strip()

    documents = Document.objects.select_related('owner').order_by('-uploaded_at')

    if query:
        documents = documents.filter(title__icontains=query)

    return render(request, 'accounts/admin_documents.html', {
        'documents': documents,
        'query': query,
    })


@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'Вы вышли из системы.')
    return redirect('login')