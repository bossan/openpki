import logging

from pki.models import UserCertificate

logger = logging.getLogger(__name__)


def generate_for_user(user, ca):
    certificate = UserCertificate(
        user=user,
        ca=ca,
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


def validate(certificate):
    logger.info(f"Certificate: {certificate}")
