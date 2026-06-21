from django.db import models
from django.contrib.auth.models import User


class Document(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/')
    description = models.TextField(blank=True)
    is_confidential = models.BooleanField(default=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title