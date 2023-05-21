from django.db import models
from django.utils.translation import gettext_lazy as _

from pki.models import BaseCertificate


class Site(models.Model):
    name = models.CharField(
        max_length=255
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
    country_code = models.CharField(
        _('country code'),
        choices=BaseCertificate.COUNTRY_CHOICES,
        max_length=2,
        blank=True,
    )
    state = models.CharField(
        _('state or province'),
        max_length=64,
        blank=True,
    )

    def __str__(self):
        return self.name
