from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.contrib import messages
import os

from .models import Document
from .forms import DocumentForm


@login_required
def document_list_view(request):
    query = request.GET.get('q', '').strip()

    documents = Document.objects.filter(owner=request.user).order_by('-uploaded_at')

    if query:
        documents = documents.filter(title__icontains=query)

    form = DocumentForm()

    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.owner = request.user
            document.save()
            messages.success(request, 'Документ успешно загружен.')
            return redirect('documents')

    return render(request, 'documents/document_list.html', {
        'documents': documents,
        'form': form,
        'query': query,
    })


@login_required
def document_download_view(request, document_id):
    document = get_object_or_404(Document, id=document_id)

    is_admin = request.user.is_staff or (
        hasattr(request.user, 'profile') and request.user.profile.role == 'admin'
    )

    if document.owner != request.user and not is_admin:
        raise Http404("Файл не найден")

    if not document.file:
        raise Http404("Файл отсутствует")

    file_path = document.file.path

    if not os.path.exists(file_path):
        raise Http404("Файл не найден на сервере")

    return FileResponse(
        open(file_path, 'rb'),
        as_attachment=True,
        filename=os.path.basename(file_path)
    )


@login_required
def document_delete_view(request, document_id):
    document = get_object_or_404(Document, id=document_id, owner=request.user)

    if request.method == 'POST':
        if document.file:
            document.file.delete(save=False)
        document.delete()
        messages.warning(request, 'Документ удалён.')
        return redirect('documents')

    return render(request, 'documents/document_delete.html', {
        'document': document,
    })