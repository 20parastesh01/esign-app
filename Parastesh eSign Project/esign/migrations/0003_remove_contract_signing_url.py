# Generated by Django 2.2.17 on 2023-04-12 16:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('esign', '0002_auto_20230410_1004'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='contract',
            name='signing_url',
        ),
    ]