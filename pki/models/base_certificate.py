from datetime import timedelta

from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _

from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class BaseCertificate(models.Model):
    class KeyLengthChoices(models.IntegerChoices):
        B512 = 512, '512'
        B1024 = 1024, '1024'
        B2048 = 2048, '2048'
        B4096 = 4096, '4096'

    class DigestChoices(models.TextChoices):
        SHA1 = 'sha1', 'SHA1'
        SHA224 = 'sha224', 'SHA224'
        SHA256 = 'sha256', 'SHA256'
        SHA384 = 'sha384', 'SHA384'
        SHA512 = 'sha512', 'SHA512'

    SIGNATURE_MAPPING = {
        'sha1WithRSAEncryption': 'sha1',
        'sha224WithRSAEncryption': 'sha224',
        'sha256WithRSAEncryption': 'sha256',
        'sha384WithRSAEncryption': 'sha384',
        'sha512WithRSAEncryption': 'sha512',
    }

    COUNTRY_CHOICES = (
        (('AD', 'AD'), ('AE', 'AE'), ('AF', 'AF'), ('AG', 'AG'), ('AI', 'AI'), ('AL', 'AL'), ('AM', 'AM'),
         ('AN', 'AN'), ('AO', 'AO'), ('AQ', 'AQ'), ('AR', 'AR'), ('AS', 'AS'), ('AT', 'AT'), ('AU', 'AU'),
         ('AW', 'AW'), ('AZ', 'AZ'), ('BA', 'BA'), ('BB', 'BB'), ('BD', 'BD'), ('BE', 'BE'), ('BF', 'BF'),
         ('BG', 'BG'), ('BH', 'BH'), ('BI', 'BI'), ('BJ', 'BJ'), ('BM', 'BM'), ('BN', 'BN'), ('BO', 'BO'),
         ('BR', 'BR'), ('BS', 'BS'), ('BT', 'BT'), ('BU', 'BU'), ('BV', 'BV'), ('BW', 'BW'), ('BY', 'BY'),
         ('BZ', 'BZ'), ('CA', 'CA'), ('CC', 'CC'), ('CF', 'CF'), ('CG', 'CG'), ('CH', 'CH'), ('CI', 'CI'),
         ('CK', 'CK'), ('CL', 'CL'), ('CM', 'CM'), ('CN', 'CN'), ('CO', 'CO'), ('CR', 'CR'), ('CS', 'CS'),
         ('CU', 'CU'), ('CV', 'CV'), ('CX', 'CX'), ('CY', 'CY'), ('CZ', 'CZ'), ('DD', 'DD'), ('DE', 'DE'),
         ('DJ', 'DJ'), ('DK', 'DK'), ('DM', 'DM'), ('DO', 'DO'), ('DZ', 'DZ'), ('EC', 'EC'), ('EE', 'EE'),
         ('EG', 'EG'), ('EH', 'EH'), ('ER', 'ER'), ('ES', 'ES'), ('ET', 'ET'), ('FI', 'FI'), ('FJ', 'FJ'),
         ('FK', 'FK'), ('FM', 'FM'), ('FO', 'FO'), ('FR', 'FR'), ('FX', 'FX'), ('GA', 'GA'), ('GB', 'GB'),
         ('GD', 'GD'), ('GE', 'GE'), ('GF', 'GF'), ('GH', 'GH'), ('GI', 'GI'), ('GL', 'GL'), ('GM', 'GM'),
         ('GN', 'GN'), ('GP', 'GP'), ('GQ', 'GQ'), ('GR', 'GR'), ('GS', 'GS'), ('GT', 'GT'), ('GU', 'GU'),
         ('GW', 'GW'), ('GY', 'GY'), ('HK', 'HK'), ('HM', 'HM'), ('HN', 'HN'), ('HR', 'HR'), ('HT', 'HT'),
         ('HU', 'HU'), ('ID', 'ID'), ('IE', 'IE'), ('IL', 'IL'), ('IN', 'IN'), ('IO', 'IO'), ('IQ', 'IQ'),
         ('IR', 'IR'), ('IS', 'IS'), ('IT', 'IT'), ('JM', 'JM'), ('JO', 'JO'), ('JP', 'JP'), ('KE', 'KE'),
         ('KG', 'KG'), ('KH', 'KH'), ('KI', 'KI'), ('KM', 'KM'), ('KN', 'KN'), ('KP', 'KP'), ('KR', 'KR'),
         ('KW', 'KW'), ('KY', 'KY'), ('KZ', 'KZ'), ('LA', 'LA'), ('LB', 'LB'), ('LC', 'LC'), ('LI', 'LI'),
         ('LK', 'LK'), ('LR', 'LR'), ('LS', 'LS'), ('LT', 'LT'), ('LU', 'LU'), ('LV', 'LV'), ('LY', 'LY'),
         ('MA', 'MA'), ('MC', 'MC'), ('MD', 'MD'), ('MG', 'MG'), ('MH', 'MH'), ('ML', 'ML'), ('MM', 'MM'),
         ('MN', 'MN'), ('MO', 'MO'), ('MP', 'MP'), ('MQ', 'MQ'), ('MR', 'MR'), ('MS', 'MS'), ('MT', 'MT'),
         ('MU', 'MU'), ('MV', 'MV'), ('MW', 'MW'), ('MX', 'MX'), ('MY', 'MY'), ('MZ', 'MZ'), ('NA', 'NA'),
         ('NC', 'NC'), ('NE', 'NE'), ('NF', 'NF'), ('NG', 'NG'), ('NI', 'NI'), ('NL', 'NL'), ('NO', 'NO'),
         ('NP', 'NP'), ('NR', 'NR'), ('NT', 'NT'), ('NU', 'NU'), ('NZ', 'NZ'), ('OM', 'OM'), ('PA', 'PA'),
         ('PE', 'PE'), ('PF', 'PF'), ('PG', 'PG'), ('PH', 'PH'), ('PK', 'PK'), ('PL', 'PL'), ('PM', 'PM'),
         ('PN', 'PN'), ('PR', 'PR'), ('PT', 'PT'), ('PW', 'PW'), ('PY', 'PY'), ('QA', 'QA'), ('RE', 'RE'),
         ('RO', 'RO'), ('RU', 'RU'), ('RW', 'RW'), ('SA', 'SA'), ('SB', 'SB'), ('SC', 'SC'), ('SD', 'SD'),
         ('SE', 'SE'), ('SG', 'SG'), ('SH', 'SH'), ('SI', 'SI'), ('SJ', 'SJ'), ('SK', 'SK'), ('SL', 'SL'),
         ('SM', 'SM'), ('SN', 'SN'), ('SO', 'SO'), ('SR', 'SR'), ('ST', 'ST'), ('SU', 'SU'), ('SV', 'SV'),
         ('SY', 'SY'), ('SZ', 'SZ'), ('TC', 'TC'), ('TD', 'TD'), ('TF', 'TF'), ('TG', 'TG'), ('TH', 'TH'),
         ('TJ', 'TJ'), ('TK', 'TK'), ('TM', 'TM'), ('TN', 'TN'), ('TO', 'TO'), ('TP', 'TP'), ('TR', 'TR'),
         ('TT', 'TT'), ('TV', 'TV'), ('TW', 'TW'), ('TZ', 'TZ'), ('UA', 'UA'), ('UG', 'UG'), ('UM', 'UM'),
         ('US', 'US'), ('UY', 'UY'), ('UZ', 'UZ'), ('VA', 'VA'), ('VC', 'VC'), ('VE', 'VE'), ('VG', 'VG'),
         ('VI', 'VI'), ('VN', 'VN'), ('VU', 'VU'), ('WF', 'WF'), ('WS', 'WS'), ('YD', 'YD'), ('YE', 'YE'),
         ('YT', 'YT'), ('YU', 'YU'), ('ZA', 'ZA'), ('ZM', 'ZM'), ('ZR', 'ZR'), ('ZW', 'ZW'), ('ZZ', 'ZZ'),
         ('ZZ', 'ZZ'),
         )
    )

    class Meta:
        abstract = True

    name = models.CharField(max_length=255)

    site = models.ForeignKey(
        'pki.Site',
        related_name='site_%(class)s',
        blank=True,
        null=False,
        on_delete=models.CASCADE
    )

    key_length = models.IntegerField(
        _('key length'),
        help_text=_('bits'),
        choices=KeyLengthChoices.choices,
        default=KeyLengthChoices.B2048,
    )
    digest = models.CharField(
        _('digest algorithm'),
        help_text=_('bits'),
        choices=DigestChoices.choices,
        default=DigestChoices.SHA256,
        max_length=8,
    )

    validity_start = models.DateTimeField(
        blank=True, null=True,
        help_text=_('leave blank to use default'),
    )
    validity_end = models.DateTimeField(
        blank=True, null=True,
        help_text=_('leave blank to use default'),
    )
    country_code = models.CharField(
        _('country code'),
        choices=COUNTRY_CHOICES,
        max_length=2,
        blank=True,
    )
    state = models.CharField(
        _('state or province'),
        max_length=64,
        blank=True,
    )
    organization_name = models.CharField(
        _('organization'),
        max_length=64,
        blank=True,
    )
    organizational_unit_name = models.CharField(
        _('organizational unit name'),
        max_length=64,
        blank=True,
    )
    email = models.EmailField(
        _('email address'),
        blank=True,
    )
    common_name = models.CharField(
        _('common name'),
        max_length=64,
        blank=True,
    )

    serial_number = models.CharField(
        _('serial number'),
        help_text=_('leave blank to determine automatically'),
        blank=True,
        null=True,
        max_length=48,
    )

    certificate = models.TextField(
        blank=True,
        help_text='certificate in PEM format',
    )
    private_key = models.TextField(
        blank=True,
        help_text='private key in PEM format',
    )

    created = models.DateTimeField(_('created'), auto_now_add=True)
    modified = models.DateTimeField(_('modified'), auto_now=True)

    passphrase = models.CharField(
        max_length=64,
        blank=True,
        help_text=_('passphrase for the private key'),
    )

    def __str__(self):
        return self.name

    def _generate_serial_number(self):
        return x509.random_serial_number()

    def clean(self):
        if hasattr(self, 'ca'):
            self.site = self.ca.site

        if not self.validity_start:
            start = timezone.localtime() - timedelta(days=1)
            self.validity_start = start.replace(hour=0, minute=0, second=0, microsecond=0)

        if not self.validity_end:
            delta = timedelta(days=365)
            self.validity_end = timezone.localtime() + delta

    def _generate_subject(self, subject):
        return x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject.common_name),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, subject.email),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, subject.country_code),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, subject.state),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, subject.organization_name),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit_name),
        ])

    def add_certificate_options(self, builder: x509.CertificateBuilder):
        raise NotImplementedError("add_certificate_options needs to be implemented!")

    def _generate(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_length
        )
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(self._generate_subject(self))

        if hasattr(self, 'ca'):
            builder = builder.issuer_name(self._generate_subject(self.ca))
        else:
            builder = builder.issuer_name(self._generate_subject(self))

        builder = builder.not_valid_before(self.validity_start)
        builder = builder.not_valid_after(self.validity_end)
        builder = builder.serial_number(self.serial_number)
        builder = builder.public_key(public_key)

        builder = self.add_certificate_options(builder)

        if hasattr(self, 'ca'):
            ca_private_key = serialization.load_pem_private_key(
                data=self.ca.private_key.encode('utf-8'),
                password=self.ca.passphrase.encode('utf-8') if self.ca.passphrase else None,
            )
            certificate = builder.sign(private_key=ca_private_key, algorithm=self.ca.get_hash())
        else:
            certificate = builder.sign(private_key=private_key, algorithm=self.get_hash())

        encryption = serialization.BestAvailableEncryption(getattr(self, 'passphrase').encode('utf-8')) \
            if self.passphrase else serialization.NoEncryption()

        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        ).decode('utf-8')

        self.certificate = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')

    def get_hash(self):
        match self.digest:
            case BaseCertificate.DigestChoices.SHA1:
                return hashes.SHA1()
            case BaseCertificate.DigestChoices.SHA224:
                return hashes.SHA224()
            case BaseCertificate.DigestChoices.SHA256:
                return hashes.SHA256()
            case BaseCertificate.DigestChoices.SHA384:
                return hashes.SHA384()
            case BaseCertificate.DigestChoices.SHA512:
                return hashes.SHA512()
            case _:
                raise Exception("Hash not found")

    def save(self, *args, **kwargs):
        generate = not self.pk and not self.certificate and not self.private_key
        super().save(*args, **kwargs)

        if generate:
            self.serial_number = self._generate_serial_number() if not self.serial_number else self.serial_number
            self._generate()
            kwargs['force_insert'] = False
            super().save(*args, **kwargs)

    @cached_property
    def x509(self):
        if self.certificate:
            return crypto.load_certificate(crypto.FILETYPE_PEM, str.encode(self.certificate))

    @cached_property
    def x509_text(self):
        if self.certificate:
            text = crypto.dump_certificate(crypto.FILETYPE_TEXT, self.x509)
            return text.decode('utf-8')

    @cached_property
    def pkey(self):
        if self.private_key:
            return crypto.load_privatekey(
                crypto.FILETYPE_PEM,
                self.private_key,
                passphrase=getattr(self, 'passphrase').encode('utf-8'),
            )
