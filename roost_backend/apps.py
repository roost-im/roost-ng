from django.apps import AppConfig


class RoostBackendConfig(AppConfig):
    name = 'roost_backend'

    def ready(self):
        # pylint: disable=import-outside-toplevel, unused-import
        # This is for side-effects of hooking up signals.
        from . import signals   # noqa: F401
        super().ready()
