from django.conf.urls import url
from channels.routing import ProtocolTypeRouter, URLRouter

from roost_backend.consumers import UserSocketConsumer
# from roost_backend.middleware import JWTAuthTokenMiddleware

# pylint: disable=invalid-name
application = ProtocolTypeRouter({
    # Empty for now (http->django views is added by default)
    # This would be cool if roost did websocket auth by header.
    # 'websocket': JWTAuthTokenMiddleware(
    #     URLRouter([
    #         url(r'^v1/socket/websocket', UserSocketConsumer),
    #     ])
    # ),
    'websocket': URLRouter([
        url(r'^v1/socket/websocket', UserSocketConsumer),
    ]),
})
