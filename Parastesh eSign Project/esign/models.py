from django.db import models

import os

def get_default_document():
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        default_doc_path = os.path.join(BASE_DIR, 'staticfiles/Document.pdf')

        with open(default_doc_path, 'rb') as file:
            content = file.read()

        from django.core.files.base import ContentFile
        default_doc = ContentFile(content)
        
        return default_doc

class Contract(models.Model):
    sender_name = models.CharField(max_length=200)
    sender_email = models.EmailField()
    recipient_name = models.CharField(max_length=200)
    recipient_email = models.EmailField()
    document = models.FileField(upload_to='contracts', blank=False, null=False, default='staticfiles/Document.pdf')
