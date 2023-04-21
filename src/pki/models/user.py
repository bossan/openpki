from django.contrib.auth import get_user_model
from django.db import models


class SiteUser(models.Model):
    user = models.OneToOneField(
        get_user_model(),
        related_name='site_user',
        on_delete=models.CASCADE
    )
    site = models.ForeignKey(
        'pki.Site',
        related_name='site_users',
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return f'{self.user}@{self.site}'

    class Meta:
        unique_together = ('user', 'site')
