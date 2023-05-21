import base64
import binascii
import logging

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp, OCSPNonce, ExtensionNotFound
from datetime import timedelta
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from pki.models import UserCertificate, Certificate, CertificateAuthority


logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class OCSPView(View):

    def fail(self, status=ocsp.OCSPResponseStatus.INTERNAL_ERROR) -> HttpResponse:
        return HttpResponse(
            ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER),
            content_type='application/ocsp-response'
        )

    def handle_ocsp_request(self, request: bytes) -> HttpResponse:
        try:
            ocsp_req = ocsp.load_der_ocsp_request(request)
        except Exception:
            logger.info("Failed loading request")
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        logger.info(f"Validating certificate {ocsp_req.serial_number}")

        cert = UserCertificate.objects.filter(serial_number=ocsp_req.serial_number).first()
        if not cert:
            cert = Certificate.objects.filter(serial_number=ocsp_req.serial_number).first()
        if not cert:
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        ca = cert.ca

        try:
            responder = self.get_ocsp_cert(ca)
        except Certificate.DoesNotExist:
            return self.fail(ocsp.OCSPResponseStatus.INTERNAL_ERROR)

        if cert.is_valid():
            status = ocsp.OCSPCertStatus.GOOD
        else:
            status = ocsp.OCSPCertStatus.REVOKED

        user_cert = cert.x509.to_cryptography()
        ca_cert = ca.x509.to_cryptography()
        responder_cert = responder.x509.to_cryptography()
        responder_key = responder.pkey.to_cryptography_key()

        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=user_cert,
            issuer=ca_cert,
            algorithm=ocsp_req.hash_algorithm,
            cert_status=status,
            this_update=timezone.now(),
            next_update=timezone.now() + timedelta(seconds=3600),
            revocation_time=cert.revoked_at,
            revocation_reason=None
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)

        builder = builder.certificates([responder_cert])

        try:
            nonce = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
            builder = builder.add_extension(nonce.value, critical=nonce.critical)
        except ExtensionNotFound:
            pass

        response = builder.sign(responder_key, responder_cert.signature_hash_algorithm)

        logger.info(f"Validated certificate {ocsp_req.serial_number} with status {status}")

        return HttpResponse(
            response.public_bytes(Encoding.DER),
            content_type='application/ocsp-response'
        )

    def get(self, request, data, *args, **kwargs) -> HttpResponse:
        try:
            data = base64.b64decode(data)
        except binascii.Error:
            return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        return self.handle_ocsp_request(data)

    def post(self, request, *args, **kwargs) -> HttpResponse:
        return self.handle_ocsp_request(request.body)

    def get_ocsp_cert(self, ca: CertificateAuthority) -> Certificate:
        return Certificate.objects.get(name="OCSP Responder", ca_id=ca.id)
