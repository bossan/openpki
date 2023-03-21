import base64
import binascii
from datetime import datetime, timedelta

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import ocsp, OCSPNonce, ExtensionNotFound
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from pki.models import UserCertificate, ClientCertificate


@method_decorator(csrf_exempt, name="dispatch")
class OCSPView(View):

    def fail(self, status=ocsp.OCSPResponseStatus.INTERNAL_ERROR):
        return self.http_response(ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER))

    def http_response(self, data, status=200):
        return HttpResponse(data, status=status, content_type="application/ocsp-response")

    def handle_ocsp_requesst(self, request):
        ocsp_req = ocsp.load_der_ocsp_request(request)

        cert = UserCertificate.objects.filter(serial_number=ocsp_req.serial_number).first()
        if not cert:
            cert = ClientCertificate.objects.filter(serial_number=ocsp_req.serial_number).first()
        if not cert:
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        ca = cert.ca

        responder_cert = self.get_ocsp_cert(ca)

        if cert.revoked_at is not None:
            status = ocsp.OCSPCertStatus.REVOKED
        else:
            status = ocsp.OCSPCertStatus.GOOD

        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert.x509,
            issuer=ca.x509,
            algorithm=ocsp_req.hash_algorithm,
            cert_status=status,
            this_update=datetime.now(),
            next_update=datetime.now() + timedelta(seconds=3600),
            revocation_time=cert.revoked_at,
            revocation_reason=None
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert.x509)

        builder = builder.certificates([responder_cert.x509])

        try:
            nonce = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
            builder = builder.add_extension(nonce.value, critical=nonce.critical)
        except ExtensionNotFound:
            pass

        response = builder.sign(responder_cert.pkey, responder_cert.X509.signature_hash_algorithm)
        return self.http_response(response.public_bytes(Encoding.DER))

    def get(self, request, data, *args, **kwargs):
        try:
            data = base64.b64decode(data)
        except binascii.Error:
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        return self.handle_ocsp_request(data)

    def post(self, request, *args, **kwargs):
        try:
            ocsp_req = ocsp.load_der_ocsp_request(base64.b64decode(request.body))
        except binascii.Error:
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        return self.handle_ocsp_request(ocsp_req)

    def get_ocsp_cert(self, ca):
        return ClientCertificate.objects.get(common_name="OCSP Responder", ca_id=ca.id)
