from django.contrib import admin
from django.contrib.admin import ModelAdmin, TabularInline
from django.utils.translation import gettext_lazy as _

from pki.models import Site, SiteUser, CertificateAuthority, Certificate, UserCertificate


class SiteUserInlineInline(TabularInline):
    model = SiteUser


class SiteAdmin(ModelAdmin):
    list_display = ['name']
    inlines = [
        SiteUserInlineInline,
    ]


class CACertificateAdmin(ModelAdmin):
    readonly_fields = ['x509_text']
    actions = ['renew_action']
    list_display = ['name', 'key_length', 'digest', 'validity_start', 'validity_end']
    list_filter = ['site']

    def renew_action(self, request, queryset):
        for cert in queryset:
            cert.renew()

        self.message_user(request, _(f'Renewed {len(queryset)} certificate(s)'))

    renew_action.short_description = _('Renew selected certificates')


class CertificateAdmin(ModelAdmin):
    def revoke_action(self, request, queryset):
        for cert in queryset:
            cert.revoke()

        self.message_user(request, _(f'Revoked {len(queryset)} certificate(s)'))

    revoke_action.short_description = _('Revoke selected certificates')

    def renew_action(self, request, queryset):
        for cert in queryset:
            cert.renew()

        self.message_user(request, _(f'Renewed {len(queryset)} certificate(s)'))

    renew_action.short_description = _('Renew selected certificates')

    readonly_fields = ['site', 'x509_text', 'revoked_at']
    actions = ['revoke_action', 'renew_action']
    list_display = ['name', 'site', 'key_length', 'digest', 'ca', 'validity_start', 'validity_end', 'revoked_at']
    list_filter = ['site', 'ca', 'digest', 'key_length', 'revoked_at']


admin.site.register(Site, SiteAdmin)
admin.site.register(Certificate, CertificateAdmin)
admin.site.register(UserCertificate, CertificateAdmin)
admin.site.register(CertificateAuthority, CACertificateAdmin)
