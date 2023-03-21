from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

from pki.models import UserCertificate


class PortalHome(LoginRequiredMixin, TemplateView):
    template_name = 'portal/portal_home.html'

    def get_context_data(self, **kwargs):
        context_data = super(PortalHome, self).get_context_data(**kwargs)
        context_data['certificates'] = UserCertificate.objects.filter(user=self.request.user, revoked_at__isnull=True)
        return context_data
