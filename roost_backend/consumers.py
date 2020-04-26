import logging

from channels.generic.websocket import JsonWebsocketConsumer

from .authentication import JWTAuthentication

_LOGGER = logging.getLogger(__name__)


class UserSocketConsumer(JsonWebsocketConsumer):
    groups = ['broadcast']

    class BadMessage(Exception):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.tails = {}

    def connect(self):
        self.accept()

    def receive_json(self, content, **kwargs):
        msg_type = content.get('type')
        if self.user is None:
            # Auth or reject as needed.
            if msg_type != 'auth':
                self.close(code=4001)
                return
            _, user = JWTAuthentication.validate_token(content.get('token'), raise_on_jwt_error=False)
            if user is None:
                self.close(code=4002)
                return
            self.user = user
            self.send_json({'type': 'ready'})
            return

        # dispatch on message type, close if unrecognized.
        try:
            {
                'ping': self.on_ping,
                'new-tail': self.on_new_tail,
                'extend-tail': self.on_extend_tail,
                'close-tail': self.on_close_tail,
            }[msg_type](content)
        except (KeyError, NotImplementedError, self.BadMessage):
            self.close(code=4005)

    def on_ping(self, _content):
        self.send_json({'type': 'pong'})

    def on_new_tail(self, content):
        tail_id = content.get('id')
        start = content.get('start')
        inclusive = content.get('inclusive', False)

        if not all((isinstance(tail_id, int),
                    start is None or not isinstance(start, str),
                    isinstance(inclusive, bool))):
            raise self.BadMessage()

        if start is None:
            start = 0
        else:
            # TODO: unseal message_id `start`
            if inclusive:
                # TODO: if `inclusive`, decrement `start`
                pass

        # TODO: construct filter from `content`
        t_filter = None
        # t_filter = Filter(content)

        if tail_id in self.tails:
            # Roost frowned upon reusing tail ids in comments, and then closed the existing tail
            # before clobbering it. Let's do the same.
            _LOGGER.debug('User "%s" has reused tail id "%i".', self.user, tail_id)
            self.tails[tail_id].close()

        self.tails['tail_id'] = Tail(self, tail_id, start, t_filter)

        raise NotImplementedError()

    def on_extend_tail(self, content):
        tail_id = content.get('id')
        count = content.get('count')
        if not all((isinstance(tail_id, int),
                    isinstance(count, int))):
            raise self.BadMessage()

        raise NotImplementedError()

    def on_close_tail(self, content):
        tail_id = content.get('id')
        if not isinstance(tail_id, int):
            raise self.BadMessage()

        if tail_id in self.tails:
            self.tails.pop(tail_id).close()

    def disconenct(self, close_code):
        _LOGGER.debug('WebSocket for user "%s" closed by client with code "%s".', self.user, close_code)
        self.close()


class Tail:
    def __init__(self, socket, t_id, start, t_filter):
        self.socket = socket
        self.user = socket.user
        self.t_id = t_id
        self.last_sent = start
        self.t_filter = t_filter
        self.active = False
        self.messages_sent = 0
        self.messages_wanted = 0

    def close(self):
        self.socket = None
        # TODO: stop doing things, once we figure out what things are.
        raise NotImplementedError()

    def extend(self, count):
        pass

    def activate(self):
        pass

    def deactivate(self):
        pass

    def do_query(self):
        pass
