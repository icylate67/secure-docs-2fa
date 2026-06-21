from django import forms
from .models import Document


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file', 'description', 'is_confidential']
        labels = {
            'title': 'Название документа',
            'file': 'Файл',
            'description': 'Описание',
            'is_confidential': 'Конфиденциальный документ',
        }
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Например: Договор, отчёт, инструкция'
            }),
            'file': forms.ClearableFileInput(attrs={
                'class': 'form-control'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Краткое описание документа',
                'rows': 4
            }),
            'is_confidential': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }