from typing import Dict
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.urls import reverse_lazy
from django.views.generic import View, FormView

from pki.forms.certificate import GenerateUserCertificateForm
from pki.models import UserCertificate, CertificateAuthority

import pki.services.certificate
import pki.services.identity


class GenerateCertificateView(LoginRequiredMixin, FormView):
    template_name = 'certificate/generate.html'
    form_class = GenerateUserCertificateForm
    success_url = reverse_lazy('pki:home')

    def get_form_kwargs(self) -> Dict:
        form_kwargs = super().get_form_kwargs()
        form_kwargs['site'] = self.request.user.site_user.site
        return form_kwargs

    def form_valid(self, form) -> HttpResponse:
        if UserCertificate.objects.filter(user_id=self.request.user.id, revoked_at__isnull=True).exists():
            return HttpResponseBadRequest("<h1>Certificate already exists</h1>")

        pki.services.certificate.generate_cert_for_user(self.request.user, form.cleaned_data['ca'])
        return super().form_valid(form)


class DownloadIdentityView(LoginRequiredMixin, View):
    def get(self, request, serial, *args, **kwargs) -> HttpResponse:
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            return HttpResponseNotFound("<h1>Certificate not found</h1>")

        p12 = pki.services.identity.generate_for_certificate(cert)

        file_name = f'identity-{request.user.username}.p12'

        response = HttpResponse(p12)
        response['Content-Type'] = f'application/x-pkcs12'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response


class DownloadCertView(LoginRequiredMixin, View):
    def get(self, request, serial, *args, **kwargs) -> HttpResponse:
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


class DownloadKeyView(LoginRequiredMixin, View):
    def get(self, request, serial, *args, **kwargs) -> HttpResponse:
        cert = UserCertificate.objects.filter(serial_number=serial, user_id=request.user.id).first()
        if not cert:
            return HttpResponseNotFound("<h1>Certificate not found</h1>")

        file_name = f'{cert.name.replace(" ", "_")}.pem'

        response = HttpResponse(cert.private_key)
        response['Content-Type'] = f'application/x-pem-file'
        response['Content-Disposition'] = f'attachment; filename={file_name}'
        return response
