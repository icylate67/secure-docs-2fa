from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static


def root_redirect(request):
    return redirect('login')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', root_redirect),
    path('', include('accounts.urls')),
    path('', include('documents.urls')),
    path('', include('security.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)