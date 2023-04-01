import ipaddress

from cryptography import x509
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from pki.models.base_certificate import BaseCertificate


class CertificateAuthority(BaseCertificate):
    def add_certificate_options(self, builder: x509.CertificateBuilder):
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        return builder

    class Meta:
        verbose_name = _('CertificateAuthority')
        verbose_name_plural = _('CertificateAuthorities')


class AbstractCertificate(BaseCertificate):
    ca = models.ForeignKey(
        'pki.CertificateAuthority',
        related_name='issued_%(class)s',
        on_delete=models.CASCADE,
        verbose_name=_('Certificate Authority'),
    )

    revoked_at = models.DateTimeField(
        _('revoked at'), blank=True, null=True, default=None
    )

    ocsp_signing = models.BooleanField(
        verbose_name=_('Enable OCSP Signing'),
        default=False
    )

    client_auth = models.BooleanField(
        verbose_name=_('Enable for client authentication'),
        default=False
    )

    server_auth = models.BooleanField(
        verbose_name=_('Enable for server authentication'),
        default=False
    )

    code_signing = models.BooleanField(
        verbose_name=_('Enable Code Signing'),
        default=False
    )

    email_protection = models.BooleanField(
        verbose_name=_('Enable Email Protection'),
        default=False
    )

    time_stamping = models.BooleanField(
        verbose_name=_('Enable Time Stamping'),
        default=False
    )

    smartcard_logon = models.BooleanField(
        verbose_name=_('Enable Smartcard Logon'),
        default=False
    )

    kerberos_pkinit_kdc = models.BooleanField(
        verbose_name=_('Enable Kerberos PKINIT and KDC'),
        default=False
    )

    ipsec_ike = models.BooleanField(
        verbose_name=_('Enable IPSec IKE'),
        default=False
    )

    certificate_transparency = models.BooleanField(
        verbose_name=_('Enable Certificate Transparency'),
        default=False
    )

    def add_certificate_options(self, builder: x509.CertificateBuilder):
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        extended_usages = []

        if self.client_auth:
            extended_usages.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
        if self.server_auth:
            extended_usages.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
        if self.code_signing:
            extended_usages.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)
        if self.email_protection:
            extended_usages.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)
        if self.ocsp_signing:
            extended_usages.append(x509.ExtendedKeyUsageOID.OCSP_SIGNING)
        if self.time_stamping:
            extended_usages.append(x509.ExtendedKeyUsageOID.TIME_STAMPING)
        if self.kerberos_pkinit_kdc:
            extended_usages.append(x509.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC)
        if self.smartcard_logon:
            extended_usages.append(x509.ExtendedKeyUsageOID.SMARTCARD_LOGON)
        if self.ipsec_ike:
            extended_usages.append(x509.ExtendedKeyUsageOID.IPSEC_IKE)

        if len(extended_usages) > 0:
            builder = builder.add_extension(x509.ExtendedKeyUsage(
                extended_usages
            ), critical=True)

        return builder

    def __str__(self):
        return f'{self.name}{" - REVOKED" if self.revoked_at is not None else ""}'

    class Meta:
        abstract = True
        verbose_name = _('Certificate')
        verbose_name_plural = _('Certificates')
        unique_together = ('ca', 'serial_number')

    def revoke(self):
        if self.revoked_at is not None:
            return

        now = timezone.now()
        self.revoked_at = now
        self.save()


class Certificate(AbstractCertificate):
    class Meta:
        verbose_name = _('Certificate')
        verbose_name_plural = _('Certificates')

    def _parse_ip_address(self, ip_address):
        try:
            return ipaddress.ip_address(ip_address)
        except ValueError:
            return None

    def add_certificate_options(self, builder: x509.CertificateBuilder):
        builder = super().add_certificate_options(builder)

        subject_alternate_name = []

        if self.ip_address:
            for address in self.ip_address.split(";"):
                ip = self._parse_ip_address(address.strip())
                subject_alternate_name.append(x509.IPAddress(ip))

        if self.dns_name:
            for name in self.dns_name.split(";"):
                subject_alternate_name.append(x509.DNSName(name.strip()))

        if len(subject_alternate_name) > 0:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                subject_alternate_name
            ), critical=False)

        return builder

    ip_address = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('IPv4 and/or IPv6 addresses, separated by ;'),
        verbose_name=_('IP Address')
    )

    dns_name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_('DNS names, separated by ;'),
        verbose_name=_('DNS name')
    )


class UserCertificate(AbstractCertificate):
    class Meta:
        verbose_name = _('UserCertificate')
        verbose_name_plural = _('UserCertificates')

    user = models.ForeignKey(
        get_user_model(),
        related_name='user_certificates',
        on_delete=models.CASCADE,
        verbose_name=_('User')
    )
