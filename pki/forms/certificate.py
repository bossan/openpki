from django import forms

from pki.models import CertificateAuthority


class GenerateUserCertificateForm(forms.Form):
    ca = forms.ModelChoiceField(
        queryset=CertificateAuthority.objects.all(),
        empty_label=None
    )
