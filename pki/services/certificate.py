import logging

from django.contrib.auth import get_user_model
from pki.models import UserCertificate, CertificateAuthority


logger = logging.getLogger(__name__)


def generate_for_user(user: get_user_model(), ca: CertificateAuthority) -> UserCertificate:
    certificate = UserCertificate(
        user=user,
        ca=ca,
        site=ca.site,
        name=user.username,
        common_name=user.username,
        country_code='NL',
        state='Friesland',
        organization_name='BOSSAN',
        organizational_unit_name='Development',
        email=user.email,
        digest=UserCertificate.DigestChoices.SHA256,
        key_length=UserCertificate.KeyLengthChoices.B4096,
        client_auth=True,
    )
    certificate.full_clean()
    certificate.save()
    return certificate
