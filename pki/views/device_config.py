import uuid
import base64

from django.http import HttpResponse, HttpResponseNotFound
from django.views.generic import View
from django.template.loader import render_to_string
from django.conf import settings

from pki.models import UserCertificate

import pki.services.certificate
import pki.services.identity


class DeviceConfigView(View):
    def get(self, request, serial, *args, **kwargs):
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            return HttpResponseNotFound("<h1>No certificate found</h1>")

        pk12 = pki.services.identity.generate_for_certificate(cert)
        pk12_base64 = base64.encodebytes(pk12).decode('utf-8')
        ca_cert_base64 = base64.encodebytes(cert.ca.certificate.encode('utf-8')).decode('utf-8')

        config = render_to_string('device_config/mobileconfig.xml', {
            'pk12_password': settings.PK12_EXPORT_PASSWORD,
            'pk12_filename': f'{cert.common_name}.p12',
            'pk12_base64': pk12_base64,
            'pk12_uuid': str(uuid.uuid4()),
            'ca_cert_filename': f'{cert.ca.common_name}.crt',
            'ca_cert_base64': ca_cert_base64,
            'ca_name': f'{cert.ca.common_name}',
            'ca_cert_uuid': str(uuid.uuid4()),
            'ssid': settings.SSID,
            'profile_name': f'{cert.common_name} - {cert.organization_name}',
            'organization_name': f'{cert.organization_name}'
        })

        file_name = f'{request.user.username}.mobileconfig'

        response = HttpResponse(config)
        response['Content-Type'] = f'application/xml'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response
