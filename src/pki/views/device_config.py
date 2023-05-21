import uuid
import base64
from datetime import timezone

from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound
from django.urls import reverse_lazy
from django.views.generic import FormView
from django.template.loader import render_to_string

from pki.forms import PasswordForm
from pki.models import UserCertificate, Certificate

import pki.services.certificate
import pki.services.identity
import pki.services.smime


class DeviceConfigView(LoginRequiredMixin, FormView):
    template_name = 'certificate/set_password.html'
    form_class = PasswordForm
    success_url = reverse_lazy('pki:home')

    def form_valid(self, form):
        cert = UserCertificate.objects.filter(
            serial_number=self.kwargs.get('serial'),
            user_id=self.request.user.id,
            revoked_at__isnull=True
        ).first()

        if not cert:
            return HttpResponseNotFound("<h1>No certificate found</h1>")

        site = self.request.user.site_user.site

        if not site:
            return HttpResponseNotFound("<h1>No site found</h1>")

        export_password = form.cleaned_data.get('password')

        pk12 = pki.services.identity.generate_for_certificate(
            cert=cert,
            export_password=export_password
        )
        pk12_base64 = base64.encodebytes(pk12).decode('utf-8')
        ca_cert_base64 = base64.encodebytes(cert.ca.certificate.encode('utf-8')).decode('utf-8')

        context = {
            'profile_name': f'{cert.common_name} - {site.name}',
            'organization_name': f'{site.organization_name}',

            'pk12_password': export_password,
            'pk12_filename': f'{cert.common_name}.p12',
            'pk12_base64': pk12_base64,
            'pk12_name': f'{cert.common_name}',
            'pk12_uuid': str(uuid.uuid4()),

            'ca_cert_filename': f'{cert.ca.common_name}.crt',
            'ca_cert_base64': ca_cert_base64,
            'ca_name': f'{cert.ca.common_name}',
            'ca_cert_uuid': str(uuid.uuid4()),

            'removal_date': cert.validity_end.replace(tzinfo=timezone.utc),
        }

        config = render_to_string('device_config/mobileconfig.xml', context)

        if getattr(settings, 'SIGN_PROFILES', False):
            try:
                signing_cert = Certificate.objects.get(site_id=site.id, name='Code Signing')
                config = pki.services.smime.sign(config.encode('utf-8'), signing_cert, signing_cert.ca)
            except Certificate.DoesNotExist:
                return HttpResponseNotFound("<h1>Tried to sign, but no signing certificate found</h1>")

        file_name = f'{self.request.user.username}.mobileconfig'

        response = HttpResponse(config)
        response['Content-Type'] = 'application/xml'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response
