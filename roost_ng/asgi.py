"""
ASGI config for roost_ng project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/
"""

import os

from channels.routing import get_default_application
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roost_ng.settings')
django.setup()
_application = get_default_application()

def application(scope):
    if scope['type'] == 'websocket':
        from pprint import pprint
        pprint(scope)
        # Daphne does not deal with the daphne-root-path header for websockets,
        # so we will deal with it here.
        headers = dict(scope['headers'])
        root_path = headers.get(b'daphne-root-path', b'').decode()
        path = scope['path']
        if root_path and path.startswith(root_path):
            scope['path'] = path[len(root_path):]
    return _application(scope)
