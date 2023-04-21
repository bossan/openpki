# Generated by Django 4.2 on 2023-04-21 09:11

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CertificateAuthority',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('key_length', models.IntegerField(choices=[(512, '512'), (1024, '1024'), (2048, '2048'), (4096, '4096')], default=2048, help_text='bits', verbose_name='key length')),
                ('digest', models.CharField(choices=[('sha1', 'SHA1'), ('sha224', 'SHA224'), ('sha256', 'SHA256'), ('sha384', 'SHA384'), ('sha512', 'SHA512')], default='sha256', help_text='bits', max_length=8, verbose_name='digest algorithm')),
                ('validity_start', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('validity_end', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('country_code', models.CharField(blank=True, choices=[('AD', 'AD'), ('AE', 'AE'), ('AF', 'AF'), ('AG', 'AG'), ('AI', 'AI'), ('AL', 'AL'), ('AM', 'AM'), ('AN', 'AN'), ('AO', 'AO'), ('AQ', 'AQ'), ('AR', 'AR'), ('AS', 'AS'), ('AT', 'AT'), ('AU', 'AU'), ('AW', 'AW'), ('AZ', 'AZ'), ('BA', 'BA'), ('BB', 'BB'), ('BD', 'BD'), ('BE', 'BE'), ('BF', 'BF'), ('BG', 'BG'), ('BH', 'BH'), ('BI', 'BI'), ('BJ', 'BJ'), ('BM', 'BM'), ('BN', 'BN'), ('BO', 'BO'), ('BR', 'BR'), ('BS', 'BS'), ('BT', 'BT'), ('BU', 'BU'), ('BV', 'BV'), ('BW', 'BW'), ('BY', 'BY'), ('BZ', 'BZ'), ('CA', 'CA'), ('CC', 'CC'), ('CF', 'CF'), ('CG', 'CG'), ('CH', 'CH'), ('CI', 'CI'), ('CK', 'CK'), ('CL', 'CL'), ('CM', 'CM'), ('CN', 'CN'), ('CO', 'CO'), ('CR', 'CR'), ('CS', 'CS'), ('CU', 'CU'), ('CV', 'CV'), ('CX', 'CX'), ('CY', 'CY'), ('CZ', 'CZ'), ('DD', 'DD'), ('DE', 'DE'), ('DJ', 'DJ'), ('DK', 'DK'), ('DM', 'DM'), ('DO', 'DO'), ('DZ', 'DZ'), ('EC', 'EC'), ('EE', 'EE'), ('EG', 'EG'), ('EH', 'EH'), ('ER', 'ER'), ('ES', 'ES'), ('ET', 'ET'), ('FI', 'FI'), ('FJ', 'FJ'), ('FK', 'FK'), ('FM', 'FM'), ('FO', 'FO'), ('FR', 'FR'), ('FX', 'FX'), ('GA', 'GA'), ('GB', 'GB'), ('GD', 'GD'), ('GE', 'GE'), ('GF', 'GF'), ('GH', 'GH'), ('GI', 'GI'), ('GL', 'GL'), ('GM', 'GM'), ('GN', 'GN'), ('GP', 'GP'), ('GQ', 'GQ'), ('GR', 'GR'), ('GS', 'GS'), ('GT', 'GT'), ('GU', 'GU'), ('GW', 'GW'), ('GY', 'GY'), ('HK', 'HK'), ('HM', 'HM'), ('HN', 'HN'), ('HR', 'HR'), ('HT', 'HT'), ('HU', 'HU'), ('ID', 'ID'), ('IE', 'IE'), ('IL', 'IL'), ('IN', 'IN'), ('IO', 'IO'), ('IQ', 'IQ'), ('IR', 'IR'), ('IS', 'IS'), ('IT', 'IT'), ('JM', 'JM'), ('JO', 'JO'), ('JP', 'JP'), ('KE', 'KE'), ('KG', 'KG'), ('KH', 'KH'), ('KI', 'KI'), ('KM', 'KM'), ('KN', 'KN'), ('KP', 'KP'), ('KR', 'KR'), ('KW', 'KW'), ('KY', 'KY'), ('KZ', 'KZ'), ('LA', 'LA'), ('LB', 'LB'), ('LC', 'LC'), ('LI', 'LI'), ('LK', 'LK'), ('LR', 'LR'), ('LS', 'LS'), ('LT', 'LT'), ('LU', 'LU'), ('LV', 'LV'), ('LY', 'LY'), ('MA', 'MA'), ('MC', 'MC'), ('MD', 'MD'), ('MG', 'MG'), ('MH', 'MH'), ('ML', 'ML'), ('MM', 'MM'), ('MN', 'MN'), ('MO', 'MO'), ('MP', 'MP'), ('MQ', 'MQ'), ('MR', 'MR'), ('MS', 'MS'), ('MT', 'MT'), ('MU', 'MU'), ('MV', 'MV'), ('MW', 'MW'), ('MX', 'MX'), ('MY', 'MY'), ('MZ', 'MZ'), ('NA', 'NA'), ('NC', 'NC'), ('NE', 'NE'), ('NF', 'NF'), ('NG', 'NG'), ('NI', 'NI'), ('NL', 'NL'), ('NO', 'NO'), ('NP', 'NP'), ('NR', 'NR'), ('NT', 'NT'), ('NU', 'NU'), ('NZ', 'NZ'), ('OM', 'OM'), ('PA', 'PA'), ('PE', 'PE'), ('PF', 'PF'), ('PG', 'PG'), ('PH', 'PH'), ('PK', 'PK'), ('PL', 'PL'), ('PM', 'PM'), ('PN', 'PN'), ('PR', 'PR'), ('PT', 'PT'), ('PW', 'PW'), ('PY', 'PY'), ('QA', 'QA'), ('RE', 'RE'), ('RO', 'RO'), ('RU', 'RU'), ('RW', 'RW'), ('SA', 'SA'), ('SB', 'SB'), ('SC', 'SC'), ('SD', 'SD'), ('SE', 'SE'), ('SG', 'SG'), ('SH', 'SH'), ('SI', 'SI'), ('SJ', 'SJ'), ('SK', 'SK'), ('SL', 'SL'), ('SM', 'SM'), ('SN', 'SN'), ('SO', 'SO'), ('SR', 'SR'), ('ST', 'ST'), ('SU', 'SU'), ('SV', 'SV'), ('SY', 'SY'), ('SZ', 'SZ'), ('TC', 'TC'), ('TD', 'TD'), ('TF', 'TF'), ('TG', 'TG'), ('TH', 'TH'), ('TJ', 'TJ'), ('TK', 'TK'), ('TM', 'TM'), ('TN', 'TN'), ('TO', 'TO'), ('TP', 'TP'), ('TR', 'TR'), ('TT', 'TT'), ('TV', 'TV'), ('TW', 'TW'), ('TZ', 'TZ'), ('UA', 'UA'), ('UG', 'UG'), ('UM', 'UM'), ('US', 'US'), ('UY', 'UY'), ('UZ', 'UZ'), ('VA', 'VA'), ('VC', 'VC'), ('VE', 'VE'), ('VG', 'VG'), ('VI', 'VI'), ('VN', 'VN'), ('VU', 'VU'), ('WF', 'WF'), ('WS', 'WS'), ('YD', 'YD'), ('YE', 'YE'), ('YT', 'YT'), ('YU', 'YU'), ('ZA', 'ZA'), ('ZM', 'ZM'), ('ZR', 'ZR'), ('ZW', 'ZW'), ('ZZ', 'ZZ'), ('ZZ', 'ZZ')], max_length=2, verbose_name='country code')),
                ('state', models.CharField(blank=True, max_length=64, verbose_name='state or province')),
                ('organization_name', models.CharField(blank=True, max_length=64, verbose_name='organization')),
                ('organizational_unit_name', models.CharField(blank=True, max_length=64, verbose_name='organizational unit name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('common_name', models.CharField(blank=True, max_length=64, verbose_name='common name')),
                ('serial_number', models.CharField(blank=True, help_text='leave blank to determine automatically', max_length=48, null=True, verbose_name='serial number')),
                ('certificate', models.TextField(blank=True, help_text='certificate in PEM format')),
                ('private_key', models.TextField(blank=True, help_text='private key in PEM format')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='modified')),
                ('passphrase', models.CharField(blank=True, help_text='passphrase for the private key', max_length=64)),
            ],
            options={
                'verbose_name': 'CertificateAuthority',
                'verbose_name_plural': 'CertificateAuthorities',
            },
        ),
        migrations.CreateModel(
            name='Site',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('ssid', models.CharField(max_length=255, verbose_name='SSID')),
                ('export_password', models.CharField(help_text='Password used when exporting profiles. This password is sent in plain text to the user.', max_length=255, verbose_name='Export password')),
                ('organization_name', models.CharField(blank=True, max_length=64, verbose_name='organization')),
                ('organizational_unit_name', models.CharField(blank=True, max_length=64, verbose_name='organizational unit name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('country_code', models.CharField(blank=True, choices=[('AD', 'AD'), ('AE', 'AE'), ('AF', 'AF'), ('AG', 'AG'), ('AI', 'AI'), ('AL', 'AL'), ('AM', 'AM'), ('AN', 'AN'), ('AO', 'AO'), ('AQ', 'AQ'), ('AR', 'AR'), ('AS', 'AS'), ('AT', 'AT'), ('AU', 'AU'), ('AW', 'AW'), ('AZ', 'AZ'), ('BA', 'BA'), ('BB', 'BB'), ('BD', 'BD'), ('BE', 'BE'), ('BF', 'BF'), ('BG', 'BG'), ('BH', 'BH'), ('BI', 'BI'), ('BJ', 'BJ'), ('BM', 'BM'), ('BN', 'BN'), ('BO', 'BO'), ('BR', 'BR'), ('BS', 'BS'), ('BT', 'BT'), ('BU', 'BU'), ('BV', 'BV'), ('BW', 'BW'), ('BY', 'BY'), ('BZ', 'BZ'), ('CA', 'CA'), ('CC', 'CC'), ('CF', 'CF'), ('CG', 'CG'), ('CH', 'CH'), ('CI', 'CI'), ('CK', 'CK'), ('CL', 'CL'), ('CM', 'CM'), ('CN', 'CN'), ('CO', 'CO'), ('CR', 'CR'), ('CS', 'CS'), ('CU', 'CU'), ('CV', 'CV'), ('CX', 'CX'), ('CY', 'CY'), ('CZ', 'CZ'), ('DD', 'DD'), ('DE', 'DE'), ('DJ', 'DJ'), ('DK', 'DK'), ('DM', 'DM'), ('DO', 'DO'), ('DZ', 'DZ'), ('EC', 'EC'), ('EE', 'EE'), ('EG', 'EG'), ('EH', 'EH'), ('ER', 'ER'), ('ES', 'ES'), ('ET', 'ET'), ('FI', 'FI'), ('FJ', 'FJ'), ('FK', 'FK'), ('FM', 'FM'), ('FO', 'FO'), ('FR', 'FR'), ('FX', 'FX'), ('GA', 'GA'), ('GB', 'GB'), ('GD', 'GD'), ('GE', 'GE'), ('GF', 'GF'), ('GH', 'GH'), ('GI', 'GI'), ('GL', 'GL'), ('GM', 'GM'), ('GN', 'GN'), ('GP', 'GP'), ('GQ', 'GQ'), ('GR', 'GR'), ('GS', 'GS'), ('GT', 'GT'), ('GU', 'GU'), ('GW', 'GW'), ('GY', 'GY'), ('HK', 'HK'), ('HM', 'HM'), ('HN', 'HN'), ('HR', 'HR'), ('HT', 'HT'), ('HU', 'HU'), ('ID', 'ID'), ('IE', 'IE'), ('IL', 'IL'), ('IN', 'IN'), ('IO', 'IO'), ('IQ', 'IQ'), ('IR', 'IR'), ('IS', 'IS'), ('IT', 'IT'), ('JM', 'JM'), ('JO', 'JO'), ('JP', 'JP'), ('KE', 'KE'), ('KG', 'KG'), ('KH', 'KH'), ('KI', 'KI'), ('KM', 'KM'), ('KN', 'KN'), ('KP', 'KP'), ('KR', 'KR'), ('KW', 'KW'), ('KY', 'KY'), ('KZ', 'KZ'), ('LA', 'LA'), ('LB', 'LB'), ('LC', 'LC'), ('LI', 'LI'), ('LK', 'LK'), ('LR', 'LR'), ('LS', 'LS'), ('LT', 'LT'), ('LU', 'LU'), ('LV', 'LV'), ('LY', 'LY'), ('MA', 'MA'), ('MC', 'MC'), ('MD', 'MD'), ('MG', 'MG'), ('MH', 'MH'), ('ML', 'ML'), ('MM', 'MM'), ('MN', 'MN'), ('MO', 'MO'), ('MP', 'MP'), ('MQ', 'MQ'), ('MR', 'MR'), ('MS', 'MS'), ('MT', 'MT'), ('MU', 'MU'), ('MV', 'MV'), ('MW', 'MW'), ('MX', 'MX'), ('MY', 'MY'), ('MZ', 'MZ'), ('NA', 'NA'), ('NC', 'NC'), ('NE', 'NE'), ('NF', 'NF'), ('NG', 'NG'), ('NI', 'NI'), ('NL', 'NL'), ('NO', 'NO'), ('NP', 'NP'), ('NR', 'NR'), ('NT', 'NT'), ('NU', 'NU'), ('NZ', 'NZ'), ('OM', 'OM'), ('PA', 'PA'), ('PE', 'PE'), ('PF', 'PF'), ('PG', 'PG'), ('PH', 'PH'), ('PK', 'PK'), ('PL', 'PL'), ('PM', 'PM'), ('PN', 'PN'), ('PR', 'PR'), ('PT', 'PT'), ('PW', 'PW'), ('PY', 'PY'), ('QA', 'QA'), ('RE', 'RE'), ('RO', 'RO'), ('RU', 'RU'), ('RW', 'RW'), ('SA', 'SA'), ('SB', 'SB'), ('SC', 'SC'), ('SD', 'SD'), ('SE', 'SE'), ('SG', 'SG'), ('SH', 'SH'), ('SI', 'SI'), ('SJ', 'SJ'), ('SK', 'SK'), ('SL', 'SL'), ('SM', 'SM'), ('SN', 'SN'), ('SO', 'SO'), ('SR', 'SR'), ('ST', 'ST'), ('SU', 'SU'), ('SV', 'SV'), ('SY', 'SY'), ('SZ', 'SZ'), ('TC', 'TC'), ('TD', 'TD'), ('TF', 'TF'), ('TG', 'TG'), ('TH', 'TH'), ('TJ', 'TJ'), ('TK', 'TK'), ('TM', 'TM'), ('TN', 'TN'), ('TO', 'TO'), ('TP', 'TP'), ('TR', 'TR'), ('TT', 'TT'), ('TV', 'TV'), ('TW', 'TW'), ('TZ', 'TZ'), ('UA', 'UA'), ('UG', 'UG'), ('UM', 'UM'), ('US', 'US'), ('UY', 'UY'), ('UZ', 'UZ'), ('VA', 'VA'), ('VC', 'VC'), ('VE', 'VE'), ('VG', 'VG'), ('VI', 'VI'), ('VN', 'VN'), ('VU', 'VU'), ('WF', 'WF'), ('WS', 'WS'), ('YD', 'YD'), ('YE', 'YE'), ('YT', 'YT'), ('YU', 'YU'), ('ZA', 'ZA'), ('ZM', 'ZM'), ('ZR', 'ZR'), ('ZW', 'ZW'), ('ZZ', 'ZZ'), ('ZZ', 'ZZ')], max_length=2, verbose_name='country code')),
                ('state', models.CharField(blank=True, max_length=64, verbose_name='state or province')),
            ],
        ),
        migrations.CreateModel(
            name='UserCertificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('key_length', models.IntegerField(choices=[(512, '512'), (1024, '1024'), (2048, '2048'), (4096, '4096')], default=2048, help_text='bits', verbose_name='key length')),
                ('digest', models.CharField(choices=[('sha1', 'SHA1'), ('sha224', 'SHA224'), ('sha256', 'SHA256'), ('sha384', 'SHA384'), ('sha512', 'SHA512')], default='sha256', help_text='bits', max_length=8, verbose_name='digest algorithm')),
                ('validity_start', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('validity_end', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('country_code', models.CharField(blank=True, choices=[('AD', 'AD'), ('AE', 'AE'), ('AF', 'AF'), ('AG', 'AG'), ('AI', 'AI'), ('AL', 'AL'), ('AM', 'AM'), ('AN', 'AN'), ('AO', 'AO'), ('AQ', 'AQ'), ('AR', 'AR'), ('AS', 'AS'), ('AT', 'AT'), ('AU', 'AU'), ('AW', 'AW'), ('AZ', 'AZ'), ('BA', 'BA'), ('BB', 'BB'), ('BD', 'BD'), ('BE', 'BE'), ('BF', 'BF'), ('BG', 'BG'), ('BH', 'BH'), ('BI', 'BI'), ('BJ', 'BJ'), ('BM', 'BM'), ('BN', 'BN'), ('BO', 'BO'), ('BR', 'BR'), ('BS', 'BS'), ('BT', 'BT'), ('BU', 'BU'), ('BV', 'BV'), ('BW', 'BW'), ('BY', 'BY'), ('BZ', 'BZ'), ('CA', 'CA'), ('CC', 'CC'), ('CF', 'CF'), ('CG', 'CG'), ('CH', 'CH'), ('CI', 'CI'), ('CK', 'CK'), ('CL', 'CL'), ('CM', 'CM'), ('CN', 'CN'), ('CO', 'CO'), ('CR', 'CR'), ('CS', 'CS'), ('CU', 'CU'), ('CV', 'CV'), ('CX', 'CX'), ('CY', 'CY'), ('CZ', 'CZ'), ('DD', 'DD'), ('DE', 'DE'), ('DJ', 'DJ'), ('DK', 'DK'), ('DM', 'DM'), ('DO', 'DO'), ('DZ', 'DZ'), ('EC', 'EC'), ('EE', 'EE'), ('EG', 'EG'), ('EH', 'EH'), ('ER', 'ER'), ('ES', 'ES'), ('ET', 'ET'), ('FI', 'FI'), ('FJ', 'FJ'), ('FK', 'FK'), ('FM', 'FM'), ('FO', 'FO'), ('FR', 'FR'), ('FX', 'FX'), ('GA', 'GA'), ('GB', 'GB'), ('GD', 'GD'), ('GE', 'GE'), ('GF', 'GF'), ('GH', 'GH'), ('GI', 'GI'), ('GL', 'GL'), ('GM', 'GM'), ('GN', 'GN'), ('GP', 'GP'), ('GQ', 'GQ'), ('GR', 'GR'), ('GS', 'GS'), ('GT', 'GT'), ('GU', 'GU'), ('GW', 'GW'), ('GY', 'GY'), ('HK', 'HK'), ('HM', 'HM'), ('HN', 'HN'), ('HR', 'HR'), ('HT', 'HT'), ('HU', 'HU'), ('ID', 'ID'), ('IE', 'IE'), ('IL', 'IL'), ('IN', 'IN'), ('IO', 'IO'), ('IQ', 'IQ'), ('IR', 'IR'), ('IS', 'IS'), ('IT', 'IT'), ('JM', 'JM'), ('JO', 'JO'), ('JP', 'JP'), ('KE', 'KE'), ('KG', 'KG'), ('KH', 'KH'), ('KI', 'KI'), ('KM', 'KM'), ('KN', 'KN'), ('KP', 'KP'), ('KR', 'KR'), ('KW', 'KW'), ('KY', 'KY'), ('KZ', 'KZ'), ('LA', 'LA'), ('LB', 'LB'), ('LC', 'LC'), ('LI', 'LI'), ('LK', 'LK'), ('LR', 'LR'), ('LS', 'LS'), ('LT', 'LT'), ('LU', 'LU'), ('LV', 'LV'), ('LY', 'LY'), ('MA', 'MA'), ('MC', 'MC'), ('MD', 'MD'), ('MG', 'MG'), ('MH', 'MH'), ('ML', 'ML'), ('MM', 'MM'), ('MN', 'MN'), ('MO', 'MO'), ('MP', 'MP'), ('MQ', 'MQ'), ('MR', 'MR'), ('MS', 'MS'), ('MT', 'MT'), ('MU', 'MU'), ('MV', 'MV'), ('MW', 'MW'), ('MX', 'MX'), ('MY', 'MY'), ('MZ', 'MZ'), ('NA', 'NA'), ('NC', 'NC'), ('NE', 'NE'), ('NF', 'NF'), ('NG', 'NG'), ('NI', 'NI'), ('NL', 'NL'), ('NO', 'NO'), ('NP', 'NP'), ('NR', 'NR'), ('NT', 'NT'), ('NU', 'NU'), ('NZ', 'NZ'), ('OM', 'OM'), ('PA', 'PA'), ('PE', 'PE'), ('PF', 'PF'), ('PG', 'PG'), ('PH', 'PH'), ('PK', 'PK'), ('PL', 'PL'), ('PM', 'PM'), ('PN', 'PN'), ('PR', 'PR'), ('PT', 'PT'), ('PW', 'PW'), ('PY', 'PY'), ('QA', 'QA'), ('RE', 'RE'), ('RO', 'RO'), ('RU', 'RU'), ('RW', 'RW'), ('SA', 'SA'), ('SB', 'SB'), ('SC', 'SC'), ('SD', 'SD'), ('SE', 'SE'), ('SG', 'SG'), ('SH', 'SH'), ('SI', 'SI'), ('SJ', 'SJ'), ('SK', 'SK'), ('SL', 'SL'), ('SM', 'SM'), ('SN', 'SN'), ('SO', 'SO'), ('SR', 'SR'), ('ST', 'ST'), ('SU', 'SU'), ('SV', 'SV'), ('SY', 'SY'), ('SZ', 'SZ'), ('TC', 'TC'), ('TD', 'TD'), ('TF', 'TF'), ('TG', 'TG'), ('TH', 'TH'), ('TJ', 'TJ'), ('TK', 'TK'), ('TM', 'TM'), ('TN', 'TN'), ('TO', 'TO'), ('TP', 'TP'), ('TR', 'TR'), ('TT', 'TT'), ('TV', 'TV'), ('TW', 'TW'), ('TZ', 'TZ'), ('UA', 'UA'), ('UG', 'UG'), ('UM', 'UM'), ('US', 'US'), ('UY', 'UY'), ('UZ', 'UZ'), ('VA', 'VA'), ('VC', 'VC'), ('VE', 'VE'), ('VG', 'VG'), ('VI', 'VI'), ('VN', 'VN'), ('VU', 'VU'), ('WF', 'WF'), ('WS', 'WS'), ('YD', 'YD'), ('YE', 'YE'), ('YT', 'YT'), ('YU', 'YU'), ('ZA', 'ZA'), ('ZM', 'ZM'), ('ZR', 'ZR'), ('ZW', 'ZW'), ('ZZ', 'ZZ'), ('ZZ', 'ZZ')], max_length=2, verbose_name='country code')),
                ('state', models.CharField(blank=True, max_length=64, verbose_name='state or province')),
                ('organization_name', models.CharField(blank=True, max_length=64, verbose_name='organization')),
                ('organizational_unit_name', models.CharField(blank=True, max_length=64, verbose_name='organizational unit name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('common_name', models.CharField(blank=True, max_length=64, verbose_name='common name')),
                ('serial_number', models.CharField(blank=True, help_text='leave blank to determine automatically', max_length=48, null=True, verbose_name='serial number')),
                ('certificate', models.TextField(blank=True, help_text='certificate in PEM format')),
                ('private_key', models.TextField(blank=True, help_text='private key in PEM format')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='modified')),
                ('passphrase', models.CharField(blank=True, help_text='passphrase for the private key', max_length=64)),
                ('revoked_at', models.DateTimeField(blank=True, default=None, null=True, verbose_name='revoked at')),
                ('ocsp_signing', models.BooleanField(default=False, verbose_name='Enable OCSP Signing')),
                ('client_auth', models.BooleanField(default=False, verbose_name='Enable for client authentication')),
                ('server_auth', models.BooleanField(default=False, verbose_name='Enable for server authentication')),
                ('code_signing', models.BooleanField(default=False, verbose_name='Enable Code Signing')),
                ('email_protection', models.BooleanField(default=False, verbose_name='Enable Email Protection')),
                ('time_stamping', models.BooleanField(default=False, verbose_name='Enable Time Stamping')),
                ('smartcard_logon', models.BooleanField(default=False, verbose_name='Enable Smartcard Logon')),
                ('kerberos_pkinit_kdc', models.BooleanField(default=False, verbose_name='Enable Kerberos PKINIT and KDC')),
                ('ipsec_ike', models.BooleanField(default=False, verbose_name='Enable IPSec IKE')),
                ('certificate_transparency', models.BooleanField(default=False, verbose_name='Enable Certificate Transparency')),
                ('ca', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issued_%(class)s', to='pki.certificateauthority', verbose_name='Certificate Authority')),
                ('site', models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='site_%(class)s', to='pki.site')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_certificates', to=settings.AUTH_USER_MODEL, verbose_name='User')),
            ],
            options={
                'verbose_name': 'UserCertificate',
                'verbose_name_plural': 'UserCertificates',
            },
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='site',
            field=models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='site_%(class)s', to='pki.site'),
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('key_length', models.IntegerField(choices=[(512, '512'), (1024, '1024'), (2048, '2048'), (4096, '4096')], default=2048, help_text='bits', verbose_name='key length')),
                ('digest', models.CharField(choices=[('sha1', 'SHA1'), ('sha224', 'SHA224'), ('sha256', 'SHA256'), ('sha384', 'SHA384'), ('sha512', 'SHA512')], default='sha256', help_text='bits', max_length=8, verbose_name='digest algorithm')),
                ('validity_start', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('validity_end', models.DateTimeField(blank=True, help_text='leave blank to use default', null=True)),
                ('country_code', models.CharField(blank=True, choices=[('AD', 'AD'), ('AE', 'AE'), ('AF', 'AF'), ('AG', 'AG'), ('AI', 'AI'), ('AL', 'AL'), ('AM', 'AM'), ('AN', 'AN'), ('AO', 'AO'), ('AQ', 'AQ'), ('AR', 'AR'), ('AS', 'AS'), ('AT', 'AT'), ('AU', 'AU'), ('AW', 'AW'), ('AZ', 'AZ'), ('BA', 'BA'), ('BB', 'BB'), ('BD', 'BD'), ('BE', 'BE'), ('BF', 'BF'), ('BG', 'BG'), ('BH', 'BH'), ('BI', 'BI'), ('BJ', 'BJ'), ('BM', 'BM'), ('BN', 'BN'), ('BO', 'BO'), ('BR', 'BR'), ('BS', 'BS'), ('BT', 'BT'), ('BU', 'BU'), ('BV', 'BV'), ('BW', 'BW'), ('BY', 'BY'), ('BZ', 'BZ'), ('CA', 'CA'), ('CC', 'CC'), ('CF', 'CF'), ('CG', 'CG'), ('CH', 'CH'), ('CI', 'CI'), ('CK', 'CK'), ('CL', 'CL'), ('CM', 'CM'), ('CN', 'CN'), ('CO', 'CO'), ('CR', 'CR'), ('CS', 'CS'), ('CU', 'CU'), ('CV', 'CV'), ('CX', 'CX'), ('CY', 'CY'), ('CZ', 'CZ'), ('DD', 'DD'), ('DE', 'DE'), ('DJ', 'DJ'), ('DK', 'DK'), ('DM', 'DM'), ('DO', 'DO'), ('DZ', 'DZ'), ('EC', 'EC'), ('EE', 'EE'), ('EG', 'EG'), ('EH', 'EH'), ('ER', 'ER'), ('ES', 'ES'), ('ET', 'ET'), ('FI', 'FI'), ('FJ', 'FJ'), ('FK', 'FK'), ('FM', 'FM'), ('FO', 'FO'), ('FR', 'FR'), ('FX', 'FX'), ('GA', 'GA'), ('GB', 'GB'), ('GD', 'GD'), ('GE', 'GE'), ('GF', 'GF'), ('GH', 'GH'), ('GI', 'GI'), ('GL', 'GL'), ('GM', 'GM'), ('GN', 'GN'), ('GP', 'GP'), ('GQ', 'GQ'), ('GR', 'GR'), ('GS', 'GS'), ('GT', 'GT'), ('GU', 'GU'), ('GW', 'GW'), ('GY', 'GY'), ('HK', 'HK'), ('HM', 'HM'), ('HN', 'HN'), ('HR', 'HR'), ('HT', 'HT'), ('HU', 'HU'), ('ID', 'ID'), ('IE', 'IE'), ('IL', 'IL'), ('IN', 'IN'), ('IO', 'IO'), ('IQ', 'IQ'), ('IR', 'IR'), ('IS', 'IS'), ('IT', 'IT'), ('JM', 'JM'), ('JO', 'JO'), ('JP', 'JP'), ('KE', 'KE'), ('KG', 'KG'), ('KH', 'KH'), ('KI', 'KI'), ('KM', 'KM'), ('KN', 'KN'), ('KP', 'KP'), ('KR', 'KR'), ('KW', 'KW'), ('KY', 'KY'), ('KZ', 'KZ'), ('LA', 'LA'), ('LB', 'LB'), ('LC', 'LC'), ('LI', 'LI'), ('LK', 'LK'), ('LR', 'LR'), ('LS', 'LS'), ('LT', 'LT'), ('LU', 'LU'), ('LV', 'LV'), ('LY', 'LY'), ('MA', 'MA'), ('MC', 'MC'), ('MD', 'MD'), ('MG', 'MG'), ('MH', 'MH'), ('ML', 'ML'), ('MM', 'MM'), ('MN', 'MN'), ('MO', 'MO'), ('MP', 'MP'), ('MQ', 'MQ'), ('MR', 'MR'), ('MS', 'MS'), ('MT', 'MT'), ('MU', 'MU'), ('MV', 'MV'), ('MW', 'MW'), ('MX', 'MX'), ('MY', 'MY'), ('MZ', 'MZ'), ('NA', 'NA'), ('NC', 'NC'), ('NE', 'NE'), ('NF', 'NF'), ('NG', 'NG'), ('NI', 'NI'), ('NL', 'NL'), ('NO', 'NO'), ('NP', 'NP'), ('NR', 'NR'), ('NT', 'NT'), ('NU', 'NU'), ('NZ', 'NZ'), ('OM', 'OM'), ('PA', 'PA'), ('PE', 'PE'), ('PF', 'PF'), ('PG', 'PG'), ('PH', 'PH'), ('PK', 'PK'), ('PL', 'PL'), ('PM', 'PM'), ('PN', 'PN'), ('PR', 'PR'), ('PT', 'PT'), ('PW', 'PW'), ('PY', 'PY'), ('QA', 'QA'), ('RE', 'RE'), ('RO', 'RO'), ('RU', 'RU'), ('RW', 'RW'), ('SA', 'SA'), ('SB', 'SB'), ('SC', 'SC'), ('SD', 'SD'), ('SE', 'SE'), ('SG', 'SG'), ('SH', 'SH'), ('SI', 'SI'), ('SJ', 'SJ'), ('SK', 'SK'), ('SL', 'SL'), ('SM', 'SM'), ('SN', 'SN'), ('SO', 'SO'), ('SR', 'SR'), ('ST', 'ST'), ('SU', 'SU'), ('SV', 'SV'), ('SY', 'SY'), ('SZ', 'SZ'), ('TC', 'TC'), ('TD', 'TD'), ('TF', 'TF'), ('TG', 'TG'), ('TH', 'TH'), ('TJ', 'TJ'), ('TK', 'TK'), ('TM', 'TM'), ('TN', 'TN'), ('TO', 'TO'), ('TP', 'TP'), ('TR', 'TR'), ('TT', 'TT'), ('TV', 'TV'), ('TW', 'TW'), ('TZ', 'TZ'), ('UA', 'UA'), ('UG', 'UG'), ('UM', 'UM'), ('US', 'US'), ('UY', 'UY'), ('UZ', 'UZ'), ('VA', 'VA'), ('VC', 'VC'), ('VE', 'VE'), ('VG', 'VG'), ('VI', 'VI'), ('VN', 'VN'), ('VU', 'VU'), ('WF', 'WF'), ('WS', 'WS'), ('YD', 'YD'), ('YE', 'YE'), ('YT', 'YT'), ('YU', 'YU'), ('ZA', 'ZA'), ('ZM', 'ZM'), ('ZR', 'ZR'), ('ZW', 'ZW'), ('ZZ', 'ZZ'), ('ZZ', 'ZZ')], max_length=2, verbose_name='country code')),
                ('state', models.CharField(blank=True, max_length=64, verbose_name='state or province')),
                ('organization_name', models.CharField(blank=True, max_length=64, verbose_name='organization')),
                ('organizational_unit_name', models.CharField(blank=True, max_length=64, verbose_name='organizational unit name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('common_name', models.CharField(blank=True, max_length=64, verbose_name='common name')),
                ('serial_number', models.CharField(blank=True, help_text='leave blank to determine automatically', max_length=48, null=True, verbose_name='serial number')),
                ('certificate', models.TextField(blank=True, help_text='certificate in PEM format')),
                ('private_key', models.TextField(blank=True, help_text='private key in PEM format')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='created')),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='modified')),
                ('passphrase', models.CharField(blank=True, help_text='passphrase for the private key', max_length=64)),
                ('revoked_at', models.DateTimeField(blank=True, default=None, null=True, verbose_name='revoked at')),
                ('ocsp_signing', models.BooleanField(default=False, verbose_name='Enable OCSP Signing')),
                ('client_auth', models.BooleanField(default=False, verbose_name='Enable for client authentication')),
                ('server_auth', models.BooleanField(default=False, verbose_name='Enable for server authentication')),
                ('code_signing', models.BooleanField(default=False, verbose_name='Enable Code Signing')),
                ('email_protection', models.BooleanField(default=False, verbose_name='Enable Email Protection')),
                ('time_stamping', models.BooleanField(default=False, verbose_name='Enable Time Stamping')),
                ('smartcard_logon', models.BooleanField(default=False, verbose_name='Enable Smartcard Logon')),
                ('kerberos_pkinit_kdc', models.BooleanField(default=False, verbose_name='Enable Kerberos PKINIT and KDC')),
                ('ipsec_ike', models.BooleanField(default=False, verbose_name='Enable IPSec IKE')),
                ('certificate_transparency', models.BooleanField(default=False, verbose_name='Enable Certificate Transparency')),
                ('ip_address', models.CharField(blank=True, help_text='IPv4 and/or IPv6 addresses, separated by ;', max_length=255, verbose_name='IP Address')),
                ('dns_name', models.CharField(blank=True, help_text='DNS names, separated by ;', max_length=255, verbose_name='DNS name')),
                ('ca', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issued_%(class)s', to='pki.certificateauthority', verbose_name='Certificate Authority')),
                ('site', models.ForeignKey(blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='site_%(class)s', to='pki.site')),
            ],
            options={
                'verbose_name': 'Certificate',
                'verbose_name_plural': 'Certificates',
            },
        ),
        migrations.CreateModel(
            name='SiteUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('site', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='site_users', to='pki.site')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='site_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'site')},
            },
        ),
    ]
