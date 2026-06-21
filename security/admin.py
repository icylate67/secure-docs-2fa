from django.contrib import admin
from .models import MFASettings, EmailOTPCode, SecurityLog

admin.site.register(MFASettings)
admin.site.register(EmailOTPCode)
admin.site.register(SecurityLog)