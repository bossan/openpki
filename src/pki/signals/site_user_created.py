from django.conf import settings
from django.db import models
from django.dispatch import receiver

from pki.models import SiteUser, CertificateAuthority

import pki.services.certificate


@receiver(models.signals.post_save, sender=SiteUser)
def after_site_user_created(sender, instance: SiteUser, created: bool, *args, **kwargs):  # noqa
    if not created or not getattr(settings, 'GENERATE_CERT_ON_CREATE', False):
        return

    ca = CertificateAuthority.objects.filter(site_id=instance.site_id).first()

    if ca:
        pki.services.certificate.generate_cert_for_user(user=instance.user, ca=ca)
