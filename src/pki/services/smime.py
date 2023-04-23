from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7

from pki.models import BaseCertificate, CertificateAuthority


def sign(data: bytes, signing_cert: BaseCertificate, ca: CertificateAuthority) -> bytes:
    cert = x509.load_pem_x509_certificate(signing_cert.certificate.encode('utf-8'))
    ca = x509.load_pem_x509_certificate(ca.certificate.encode('utf-8'))
    key = serialization.load_pem_private_key(
        signing_cert.private_key.encode('utf-8'),
        password=signing_cert.passphrase.encode('utf-8') if signing_cert.passphrase else None
    )

    return pkcs7.PKCS7SignatureBuilder(
        data=data,
        signers=[
            (cert, key, hashes.SHA512()),
        ],
        additional_certs=[ca],
    ).sign(
        serialization.Encoding.DER, options=[],
    )
