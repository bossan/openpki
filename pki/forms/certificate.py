from django import forms

from pki.models import CertificateAuthority


class GenerateUserCertificateForm(forms.Form):
    ca = forms.ModelChoiceField(
        queryset=CertificateAuthority.objects.all(),
        empty_label=None
    )

    def __init__(self, site, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['ca'].queryset = CertificateAuthority.objects.filter(site_id=site.id)
