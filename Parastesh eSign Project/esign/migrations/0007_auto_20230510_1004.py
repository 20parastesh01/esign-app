# Generated by Django 2.2.17 on 2023-05-10 05:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('esign', '0006_contract_document'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contract',
            name='document',
            field=models.FileField(default='staticfiles/Document.pdf', upload_to=''),
        ),
    ]
