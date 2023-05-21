from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12, PrivateFormat

from pki.models import BaseCertificate


def generate_for_certificate(cert: BaseCertificate, export_password: str) -> bytes:
    if not export_password:
        raise Exception("export_password cannot be empty")

    pem_cert = x509.load_pem_x509_certificate(
        data=cert.certificate.encode('utf-8')
    )
    pem_key = load_pem_private_key(
        data=cert.private_key.encode('utf-8'),
        password=cert.passphrase.encode('utf-8') if cert.passphrase else None
    )

    encryption = (
        PrivateFormat.PKCS12.encryption_builder().
        kdf_rounds(50000).
        key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).

        # Unfortunately SHA1 is necessary here since other algorithms are not guaranteed to be supported
        hmac_hash(hashes.SHA1()).build(export_password.encode('utf-8'))  # nosec
    )

    return pkcs12.serialize_key_and_certificates(
        name=cert.name.encode('utf-8'),
        key=pem_key,
        cert=pem_cert,
        cas=None,
        encryption_algorithm=encryption
    )
