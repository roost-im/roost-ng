import os

from django.utils import autoreload
from daphne.management.commands.runserver import Command as DaphneRunserverCommand

from ...subscribers import Manager as SubscriberManager


class Command(DaphneRunserverCommand):
    """Start and stop user processes when running channels dev server."""
    def handle(self, *args, **options):
        sm_enabled = False
        if options["use_reloader"]:
            if os.environ.get(autoreload.DJANGO_AUTORELOAD_ENV) == 'true':
                sm_enabled = True
        else:
            sm_enabled = True

        with SubscriberManager(sm_enabled):
            # Dispatch upward
            super().handle(*args, **options)
