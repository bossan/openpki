from django.urls import path, re_path
from pki.views import DeviceConfigView, DownloadCertView, DownloadIdentityView, DownloadKeyView,\
    GenerateCertificateView, OCSPView, PortalHome

app_name = "pki"

urlpatterns = [
    re_path(r'^download-cert/(?P<serial>[0-9]{32,48})$', DownloadCertView.as_view(), name='download-cert'),
    re_path(r'^download-identity/(?P<serial>[0-9]{32,48})$', DownloadIdentityView.as_view(), name='download-identity'),
    re_path(r'^download-key/(?P<serial>[0-9]{32,48})$', DownloadKeyView.as_view(), name='download-key'),
    re_path(r'^device-config/(?P<serial>[0-9]{32,48})$', DeviceConfigView.as_view(), name='device-config'),
    path('generate', GenerateCertificateView.as_view(), name='generate'),
    re_path(r'^ocsp/?$', OCSPView.as_view(), name='ocsp'),
    path('', PortalHome.as_view(), name='home'),
]
