from channels.middleware import BaseMiddleware


class DaphneRootPathForWebsockets(BaseMiddleware):
    # pylint: disable=too-few-public-methods
    async def __call__(self, scope, receive, send):
        # Copy scope to stop changes going upstream
        scope = dict(scope)
        # Daphne does not deal with the daphne-root-path header for websockets,
        # so we will deal with it here.
        headers = dict(scope['headers'])
        root_path = headers.get(b'daphne-root-path', b'').decode()
        path = scope['path']
        if root_path and path.startswith(root_path):
            scope['path'] = path[len(root_path):]
        return await self.inner(scope, receive, send)
