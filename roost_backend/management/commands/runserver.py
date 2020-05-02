import os

from django.utils import autoreload
from channels.management.commands.runserver import Command as ChannelsRunserverCommand

from ...user_process import Manager as UserProcessManager


class Command(ChannelsRunserverCommand):
    """Start and stop user processes when running channels dev server."""
    def handle(self, *args, **options):
        upm = None
        if options["use_reloader"]:
            if os.environ.get(autoreload.DJANGO_AUTORELOAD_ENV) == 'true':
                upm = UserProcessManager()
        else:
            upm = UserProcessManager()

        try:
            if upm:
                upm.start()
            # Dispatch upward
            super().handle(*args, **options)
        finally:
            if upm:
                upm.stop()
