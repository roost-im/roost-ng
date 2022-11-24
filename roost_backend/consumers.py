import logging

from asgiref.sync import async_to_sync
from channels.generic.websocket import JsonWebsocketConsumer
from djangorestframework_camel_case.util import camelize

from .authentication import JWTAuthentication
from . import filters, serializers, utils

_LOGGER = logging.getLogger(__name__)


class UserSocketConsumer(JsonWebsocketConsumer):
    class BadMessage(Exception):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.tails = {}
        self.active_tails = set()

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
            self.groups.append(utils.principal_to_user_socket_group_name(user.principal))
            async_to_sync(self.channel_layer.group_add)(self.groups[-1], self.channel_name)
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
                    start is None or isinstance(start, str),
                    isinstance(inclusive, bool))):
            raise self.BadMessage()

        if start is None:
            start = 0
        else:
            start = utils.unseal_message_id(start)
            if inclusive:
                start -= 1

        t_filter = filters.MessageFilter(**content)

        if tail_id in self.tails:
            # Roost frowned upon reusing tail ids in comments, and then closed the existing tail
            # before clobbering it. Let's do the same.
            _LOGGER.debug('User "%s" has reused tail id "%i".', self.user, tail_id)
            self.tails[tail_id].close()

        self.tails[tail_id] = Tail(self, tail_id, start, t_filter)

    def on_extend_tail(self, content):
        tail_id = content.get('id')
        count = content.get('count')
        if not all((isinstance(tail_id, int),
                    isinstance(count, int),
                    tail_id in self.tails)):
            raise self.BadMessage()
        self.tails[tail_id].extend(count)

    def on_close_tail(self, content):
        tail_id = content.get('id')
        if not isinstance(tail_id, int):
            raise self.BadMessage()

        if tail_id in self.tails:
            self.tails.pop(tail_id).close()

    def disconnect(self, code):
        _LOGGER.debug('WebSocket for user "%s" closed by client with code "%s".', self.user, code)

        for tail in self.tails.values():
            tail.close()
        self.tails = {}

        self.close()

    # Start of Channel Layer message handlers
    def incoming_message(self, message):
        # don't iterate over active_tails itself as its size may change while we do that.
        for tail in list(self.active_tails):
            tail.on_message(message['message'])
    # End message handlers


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
        self.message_buffer = None

    def close(self):
        self.deactivate()
        self.socket = None

    def extend(self, count):
        _LOGGER.debug('tail: extending %i', count)

        self.messages_wanted = max(count - self.messages_sent,
                                   self.messages_wanted)
        self.do_query()

    def activate(self):
        if not self.active:
            self.active = True
            self.socket.active_tails.add(self)

    def deactivate(self):
        if self.active:
            self.active = False
            self.socket.active_tails.remove(self)

    def do_query(self):
        if self.socket is None:
            return

        if self.active:
            return

        if self.messages_wanted == 0:
            return

        self.activate()
        self.message_buffer = []
        qs = self.user.message_set.filter(id__gt=self.last_sent)
        qs = self.t_filter.apply_to_queryset(qs)[:self.messages_wanted]
        messages = [{'id': msg.id,
                     'payload': serializers.MessageSerializer(msg).data,
                     } for msg in list(qs)]
        _LOGGER.debug('tail query returned %i messages', len(messages))
        self.emit_messages(messages)

        if self.messages_wanted:
            message_buffer, self.message_buffer = self.message_buffer, None
            messages = [{'id': msg.id,
                         'payload': serializers.MessageSerializer(msg).data,
                         } for msg in message_buffer if msg.id > self.last_sent]
            self.emit_messages(messages)

        if not self.messages_wanted:
            self.deactivate()

    def on_message(self, message):
        if not self.socket:
            return
        if not self.t_filter.matches_message(message):
            return
        if self.last_sent >= message['id']:
            return
        if isinstance(self.message_buffer, list):
            self.message_buffer.append(message)
            return

        self.emit_messages([message])
        if self.messages_wanted == 0:
            self.deactivate()

    def emit_messages(self, messages):
        if messages:
            self.socket.send_json({
                'type': 'messages',
                'id': self.t_id,
                'messages': [camelize(msg['payload']) for msg in messages],
                'isDone': True,
            })
            count = len(messages)
            self.messages_sent += count
            if count >= self.messages_wanted:
                self.messages_wanted = 0
            else:
                self.messages_wanted -= count
            self.last_sent = messages[-1]['id']
