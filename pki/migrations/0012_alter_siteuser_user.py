# Generated by Django 4.1.7 on 2023-03-23 16:59

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0011_alter_siteuser_unique_together'),
    ]

    operations = [
        migrations.AlterField(
            model_name='siteuser',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='site_user', to=settings.AUTH_USER_MODEL),
        ),
    ]
