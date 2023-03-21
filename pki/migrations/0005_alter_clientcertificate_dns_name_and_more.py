# Generated by Django 4.1.7 on 2023-03-20 15:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0004_clientcertificate_dns_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='clientcertificate',
            name='dns_name',
            field=models.CharField(blank=True, help_text='DNS names, separated by ;', max_length=255),
        ),
        migrations.AlterField(
            model_name='clientcertificate',
            name='ip_address',
            field=models.CharField(blank=True, help_text='IPv4 and/or IPv6 addresses, separated by ;', max_length=255),
        ),
    ]
