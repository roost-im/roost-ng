from django.urls import path

from roost_backend.consumers import UserSocketConsumer

websocket_urlpatterns = [
    path('v1/socket/websocket', UserSocketConsumer.as_asgi()),
]
