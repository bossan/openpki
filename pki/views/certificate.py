
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.urls import reverse_lazy
from django.views.generic import View, FormView

from pki.forms.certificate import GenerateUserCertificateForm
from pki.models import UserCertificate, CertificateAuthority

import pki.services.certificate
import pki.services.identity


class GenerateCertificateView(FormView):
    template_name = 'certificate/generate.html'
    form_class = GenerateUserCertificateForm
    success_url = reverse_lazy('pki:home')

    def form_valid(self, form):
        if UserCertificate.objects.filter(user_id=self.request.user.id, revoked_at__isnull=True).exists():
            return HttpResponseBadRequest("<h1>Certificate already exists</h1>")

        pki.services.certificate.generate_for_user(self.request.user, form.cleaned_data['ca'])
        return super().form_valid(form)


class DownloadIdentityView(View):
    def get(self, request, serial, *args, **kwargs):
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            return HttpResponseNotFound("<h1>Certificate not found</h1>")

        p12 = pki.services.identity.generate_for_certificate(cert)

        file_name = f'identity-{request.user.username}.p12'

        response = HttpResponse(p12)
        response['Content-Type'] = f'application/x-pkcs12'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response


class DownloadCertView(View):
    def get(self, request, serial, *args, **kwargs):
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            cert = CertificateAuthority.objects.filter(serial_number=serial).first()
        if not cert:
            return HttpResponseNotFound("<h1>Certificate not found</h1>")

        file_name = f'{cert.name.replace(" ", "_")}.crt'

        response = HttpResponse(cert.certificate)
        response['Content-Type'] = f'application/x-x509-{"user" if hasattr(cert, "ca") else "ca"}-cert'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response


class DownloadKeyView(View):
    def get(self, request, serial, *args, **kwargs):
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            return HttpResponseNotFound("<h1>Certificate not found</h1>")

        file_name = f'{cert.name.replace(" ", "_")}.pem'

        response = HttpResponse(cert.private_key)
        response['Content-Type'] = f'application/x-pem-file'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response
