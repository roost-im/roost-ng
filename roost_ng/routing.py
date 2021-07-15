from django.conf.urls import url

from roost_backend.consumers import UserSocketConsumer

websocket_urlpatterns = [
    url(r'^v1/socket/websocket', UserSocketConsumer.as_asgi()),
]
