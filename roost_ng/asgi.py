"""
ASGI config for roost_ng project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/
"""

import os

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roost_ng.settings')
django.setup()

import roost_ng.routing
from roost_ng.middleware import DaphneRootPathForWebsockets


application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": DaphneRootPathForWebsockets(URLRouter(roost_ng.routing.websocket_urlpatterns)),
})
