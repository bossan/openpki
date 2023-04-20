import uuid
import base64
from datetime import timezone

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseNotFound
from django.views.generic import View
from django.template.loader import render_to_string

from pki.models import UserCertificate

import pki.services.certificate
import pki.services.identity


class DeviceConfigView(LoginRequiredMixin, View):
    def get(self, request, serial, *args, **kwargs):
        cert = UserCertificate.objects.filter(
            serial_number=serial,
            user_id=request.user.id,
            revoked_at__isnull=True
        ).first()

        if not cert:
            return HttpResponseNotFound("<h1>No certificate found</h1>")

        site = request.user.site_user.site

        if not site:
            return HttpResponseNotFound("<h1>No site found</h1>")

        pk12 = pki.services.identity.generate_for_certificate(cert)
        pk12_base64 = base64.encodebytes(pk12).decode('utf-8')
        ca_cert_base64 = base64.encodebytes(cert.ca.certificate.encode('utf-8')).decode('utf-8')

        context = {
            'profile_name': f'{cert.common_name} - {site.name}',
            'organization_name': f'{site.organization_name}',
            'ssid': site.ssid,

            'pk12_password': site.export_password,
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

        # radius_cert = cert.ca.issued_clientcertificate.filter(name='Radius').first()
        # radius_cert = None
        #
        # if radius_cert:
        #     radius_cert_base64 = base64.encodebytes(radius_cert.certificate.encode('utf-8')).decode('utf-8')
        #     context.update({
        #         'radius_cert_filename': f'{radius_cert.common_name}.crt',
        #         'radius_cert_base64': radius_cert_base64,
        #         'radius_name': radius_cert.common_name,
        #         'radius_cert_uuid': str(uuid.uuid4()),
        #     })

        config = render_to_string('device_config/mobileconfig.xml', context)

        file_name = f'{request.user.username}.mobileconfig'

        response = HttpResponse(config)
        response['Content-Type'] = 'application/xml'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response
