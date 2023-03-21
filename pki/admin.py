from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.admin import ModelAdmin
from django.utils.translation import gettext_lazy as _

from pki.models.user import User
from pki.models import CertificateAuthority, ClientCertificate, UserCertificate


class CACertificateAdmin(ModelAdmin):
    readonly_fields = ['x509_text']
    list_display = ['name', 'key_length', 'digest', 'validity_start', 'validity_end']


class CertificateAdmin(ModelAdmin):
    def revoke_action(self, request, queryset):
        for cert in queryset:
            cert.revoke()

        self.message_user(request, _(f'Revoked {len(queryset)} certificate(s)'))

    revoke_action.short_description = _('Revoke selected certificates')

    readonly_fields = ['x509_text', 'revoked_at']
    actions = ['revoke_action']
    list_display = ['name', 'key_length', 'digest', 'ca', 'validity_start', 'validity_end', 'revoked_at']
    list_filter = ['ca', 'digest', 'key_length', 'revoked_at']


admin.site.register(User, UserAdmin)
admin.site.register(UserCertificate, CertificateAdmin)
admin.site.register(ClientCertificate, CertificateAdmin)
admin.site.register(CertificateAuthority, CACertificateAdmin)

