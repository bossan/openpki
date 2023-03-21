# Generated by Django 4.1.7 on 2023-03-21 19:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0006_alter_clientcertificate_dns_name_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='clientcertificate',
            name='certificate_transparency',
            field=models.BooleanField(default=False, verbose_name='Enable Certificate Transparency'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='client_auth',
            field=models.BooleanField(default=False, verbose_name='Enable for client authentication'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='code_signing',
            field=models.BooleanField(default=False, verbose_name='Enable Code Signing'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='email_protection',
            field=models.BooleanField(default=False, verbose_name='Enable Email Protection'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='ipsec_ike',
            field=models.BooleanField(default=False, verbose_name='Enable IPSec IKE'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='kerberos_pkinit_kdc',
            field=models.BooleanField(default=False, verbose_name='Enable Kerberos PKINIT and KDC'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='ocsp_signing',
            field=models.BooleanField(default=False, verbose_name='Enable OCSP Signing'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='server_auth',
            field=models.BooleanField(default=False, verbose_name='Enable for server authentication'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='smartcard_logon',
            field=models.BooleanField(default=False, verbose_name='Enable Smartcard Logon'),
        ),
        migrations.AddField(
            model_name='clientcertificate',
            name='time_stamping',
            field=models.BooleanField(default=False, verbose_name='Enable Time Stamping'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='certificate_transparency',
            field=models.BooleanField(default=False, verbose_name='Enable Certificate Transparency'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='client_auth',
            field=models.BooleanField(default=False, verbose_name='Enable for client authentication'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='code_signing',
            field=models.BooleanField(default=False, verbose_name='Enable Code Signing'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='email_protection',
            field=models.BooleanField(default=False, verbose_name='Enable Email Protection'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='ipsec_ike',
            field=models.BooleanField(default=False, verbose_name='Enable IPSec IKE'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='kerberos_pkinit_kdc',
            field=models.BooleanField(default=False, verbose_name='Enable Kerberos PKINIT and KDC'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='ocsp_signing',
            field=models.BooleanField(default=False, verbose_name='Enable OCSP Signing'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='server_auth',
            field=models.BooleanField(default=False, verbose_name='Enable for server authentication'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='smartcard_logon',
            field=models.BooleanField(default=False, verbose_name='Enable Smartcard Logon'),
        ),
        migrations.AddField(
            model_name='usercertificate',
            name='time_stamping',
            field=models.BooleanField(default=False, verbose_name='Enable Time Stamping'),
        ),
    ]
