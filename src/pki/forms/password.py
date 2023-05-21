from django import forms


class PasswordForm(forms.Form):
    password = forms.CharField(
        min_length=8,
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
