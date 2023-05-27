from django.conf import settings
from django.db import models
from django.dispatch import receiver

from pki.models import Site

import pki.services.certificate


@receiver(models.signals.post_save, sender=Site)
def after_site_created(sender, instance: Site, created: bool, *args, **kwargs):  # noqa
    if not created:
        return

    ca = pki.services.certificate.generate_ca_for_site(instance)
    pki.services.certificate.generate_default_radius_cert_for_site(instance, ca)
    pki.services.certificate.generate_ocsp_signing_cert_for_site(instance, ca)

    if getattr(settings, 'SIGN_PROFILES', False):
        pki.services.certificate.generate_code_signing_cert_for_site(instance, ca)
