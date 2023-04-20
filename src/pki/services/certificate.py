import logging

from django.contrib.auth import get_user_model
from pki.models import UserCertificate, CertificateAuthority, Site, Certificate

logger = logging.getLogger(__name__)


def generate_cert_for_user(user: get_user_model(), ca: CertificateAuthority) -> UserCertificate:
    if ca.site_id != user.site_user.site_id:
        raise Exception("CA and user should be in the same site")

    site = user.site_user.site

    certificate = UserCertificate(
        user=user,
        ca=ca,
        site=site,
        name=user.username,
        common_name=user.username,
        country_code=site.country_code,
        state=site.state,
        organization_name=site.organization_name,
        organizational_unit_name=site.organizational_unit_name,
        email=user.email,
        digest=UserCertificate.DigestChoices.SHA256,
        key_length=UserCertificate.KeyLengthChoices.B4096,
        client_auth=True,
    )
    certificate.full_clean()
    certificate.save()
    return certificate


def generate_ca_for_site(site: Site) -> CertificateAuthority:
    ca = CertificateAuthority(
        site=site,
        name=f'{site.name} CA',
        common_name=f'{site.name} CA',
        country_code=site.country_code,
        state=site.state,
        organization_name=site.organization_name,
        organizational_unit_name=site.organizational_unit_name,
        email=site.email,
        digest=UserCertificate.DigestChoices.SHA256,
        key_length=UserCertificate.KeyLengthChoices.B4096,
    )
    ca.full_clean()
    ca.save()
    return ca


def generate_default_radius_cert_for_site(site: Site, ca: CertificateAuthority) -> Certificate:
    if ca.site_id != site.id:
        raise Exception(f"CA should be in site {site}")

    cert = Certificate(
        site=site,
        ca=ca,
        name=f'{site.name} RADIUS',
        common_name=f'{site.name} RADIUS',
        country_code=site.country_code,
        state=site.state,
        organization_name=site.organization_name,
        organizational_unit_name=site.organizational_unit_name,
        email=site.email,
        digest=UserCertificate.DigestChoices.SHA256,
        key_length=UserCertificate.KeyLengthChoices.B4096,
        server_auth=True
    )
    cert.full_clean()
    cert.save()
    return cert


def generate_ocsp_signing_cert_for_site(site: Site, ca: CertificateAuthority) -> Certificate:
    if ca.site_id != site.id:
        raise Exception(f"CA should be in site {site}")

    cert = Certificate(
        site=site,
        ca=ca,
        name='OCSP Responder',
        common_name=f'{site.name} OCSP Responder',
        country_code=site.country_code,
        state=site.state,
        organization_name=site.organization_name,
        organizational_unit_name=site.organizational_unit_name,
        email=site.email,
        digest=UserCertificate.DigestChoices.SHA256,
        key_length=UserCertificate.KeyLengthChoices.B4096,
        ocsp_signing=True
    )
    cert.full_clean()
    cert.save()
    return cert
