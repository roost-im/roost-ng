import os

from django.utils import autoreload
from channels.management.commands.runserver import Command as ChannelsRunserverCommand

from ...user_process import Manager as UserProcessManager


class Command(ChannelsRunserverCommand):
    """Start and stop user processes when running channels dev server."""
    def handle(self, *args, **options):
        upm_enabled = False
        if options["use_reloader"]:
            if os.environ.get(autoreload.DJANGO_AUTORELOAD_ENV) == 'true':
                upm_enabled = True
        else:
            upm_enabled = True

        with UserProcessManager(upm_enabled):
            # Dispatch upward
            super().handle(*args, **options)
