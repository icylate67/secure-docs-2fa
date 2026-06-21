from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
import re


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        label='Электронная почта',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите email'
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Введите логин'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Введите пароль'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Повторите пароль'
        })

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError('Пользователь с таким логином уже существует.')
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('Пользователь с такой электронной почтой уже существует.')
        return email

    def clean_password1(self):
        password = self.cleaned_data.get('password1', '')

        if not re.search(r'[A-ZА-Я]', password):
            raise ValidationError('Пароль должен содержать хотя бы одну заглавную букву.')

        if not re.search(r'[!@#$%^&*()_\-+=\[\]{};:,.<>?/\\|`~]', password):
            raise ValidationError('Пароль должен содержать хотя бы один специальный символ.')

        return password


class LoginForm(forms.Form):
    username = forms.CharField(
        label='Логин',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите логин'
        })
    )
    password = forms.CharField(
        label='Пароль',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите пароль'
        })
    )


class ProfileUpdateForm(forms.ModelForm):
    avatar = forms.ImageField(
        required=False,
        label='Аватар',
        widget=forms.FileInput(attrs={
            'class': 'form-control'
        })
    )

    class Meta:
        model = User
        fields = ['username']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Введите логин'
            }),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        qs = User.objects.filter(username__iexact=username).exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('Пользователь с таким логином уже существует.')
        return username

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance and hasattr(self.instance, 'profile'):
            self.fields['avatar'].initial = self.instance.profile.avatar

    def save(self, commit=True):
        user = super().save(commit=commit)

        avatar = self.cleaned_data.get('avatar')

        if hasattr(user, 'profile') and avatar is not None:
            user.profile.avatar = avatar
            user.profile.save()

        return user


class EmailChangeForm(forms.Form):
    new_email = forms.EmailField(
        label='Новый email',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите новый email'
        })
    )
    current_password = forms.CharField(
        label='Текущий пароль',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Введите текущий пароль'
        })
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_new_email(self):
        email = self.cleaned_data.get('new_email', '').strip().lower()

        if self.user.email and email == self.user.email.lower():
            raise forms.ValidationError('Этот email уже используется в текущем аккаунте.')

        if User.objects.filter(email__iexact=email).exclude(pk=self.user.pk).exists():
            raise forms.ValidationError('Пользователь с такой электронной почтой уже существует.')

        return email

    def clean_current_password(self):
        password = self.cleaned_data.get('current_password', '')
        if not self.user.check_password(password):
            raise forms.ValidationError('Неверный текущий пароль.')
        return password