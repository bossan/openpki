from django.db import models
from django.dispatch import receiver

from pki.models import Site


@receiver(models.signals.post_save, sender=Site)
def execute_after_save(sender, instance, created, *args, **kwargs):
    if not created:
        return

    