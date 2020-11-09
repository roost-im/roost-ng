import base64
import datetime
import re
import socket
import struct

from django.conf import settings
from django.db import models, transaction
import jwt

from . import secrets, utils


class User(models.Model):
    principal = models.CharField(max_length=255, unique=True)
    info = models.JSONField(default=dict)
    info_version = models.BigIntegerField(default=1)
    # TODO: add minimum token age or token generation to invalidate old tokens.

    def get_auth_token_dict(self, **claims):
        now = datetime.datetime.utcnow()
        exp = now + settings.SESSION_LIFETIME
        claims.update({
            'identity': {
                'id': self.id,
                'principal': self.principal,
            },
            'iat': now,
            'nbf': now,
            'exp': exp,
        })
        return {
            'auth_token': jwt.encode(claims, secrets.AUTHTOKEN_KEY, algorithm='HS256').decode('utf-8'),
            # Since the JWT token will have expiration to the second, drop fractional parts of the timestamp.
            'expires': int(exp.timestamp()) * 1000,
        }

    def add_subscription(self, klass, instance, recipient):
        if recipient.lower() == '%me%':
            recipient = self.principal
        if recipient.startswith('*'):
            recipient = recipient[1:]
        if recipient not in (self.principal, '') and not recipient.startswith('@'):
            raise ValueError(f'Bad recipient: {recipient}')
        class_key = klass.casefold()
        instance_key = instance.casefold()
        obj, _created = Subscription.objects.update_or_create(
            user=self, class_key=class_key, instance_key=instance_key, zrecipient=recipient,
            defaults={'zclass': klass, 'zinstance': instance_key}
        )
        return obj

    @transaction.atomic
    def add_subscriptions(self, triples):
        def _parse_triple(triple):
            return triple['zclass'], triple['zinstance'], triple['zrecipient']
        return [self.add_subscription(*_parse_triple(triple)) for triple in triples]

    @transaction.atomic
    def add_default_subscriptions(self):
        self.add_subscription('message', '*', self.principal)

    def remove_subscription(self, klass, instance, recipient):
        class_key = klass.casefold()
        instance_key = instance.casefold()
        cnt = self.subscription_set.filter(
            class_key=class_key, instance_key=instance_key, zrecipient=recipient
        ).delete()

        return (
            # Roost's API wants to return this.
            Subscription(
                user=self, class_key=class_key, instance_key=instance_key, zrecipient=recipient,
                zclass=klass, zinstance=instance_key),
            # This is maybe a useful bit of data.
            bool(cnt),
        )

    def __str__(self):
        return self.principal

    # Let's pretend we are Django user classes just enough to make things go.
    @property
    def is_authenticated(self):
        return self.id is not None

    @property
    def is_anonymous(self):
        return self.id is None

    def send_to_user_subscriber(self, msg, wait_for_response=False):
        group_name = utils.principal_to_user_subscriber_group_name(self.principal)
        return utils.send_to_group(group_name, msg, wait_for_response)

    def send_to_user_sockets(self, msg, wait_for_response=False):
        group_name = utils.principal_to_user_socket_group_name(self.principal)
        return utils.send_to_group(group_name, msg, wait_for_response)

    class Meta:
        pass


class Subscription(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    zclass = models.CharField(max_length=255)
    zinstance = models.CharField(max_length=255)
    zrecipient = models.CharField(max_length=255)
    class_key = models.CharField(max_length=255)
    instance_key = models.CharField(max_length=255)

    def __str__(self):
        return f'{self.class_key},{self.instance_key},{self.zrecipient if self.zrecipient else "*"}'

    class Meta:
        unique_together = [
            ['user', 'zrecipient', 'class_key', 'instance_key']
        ]


RE_BASE_STR = re.compile(r'(?:un)*(.*?)(?:[.]d)*')


class Message(models.Model):
    users = models.ManyToManyField('User')
    # display data
    zclass = models.CharField(max_length=255)
    zinstance = models.CharField(max_length=255)
    # search data
    class_key = models.CharField(max_length=255)
    instance_key = models.CharField(max_length=255)
    class_key_base = models.CharField(max_length=255)
    instance_key_base = models.CharField(max_length=255)
    # date in zgram
    time = models.DateTimeField()
    # date we got zgram
    receive_time = models.DateTimeField(auto_now_add=True)

    # more zgram fields
    auth = models.BooleanField()
    sender = models.CharField(max_length=255, db_index=True)
    recipient = models.CharField(max_length=255, db_index=True, blank=True)

    # empty for non-personals; sender for incoming, recipient for outgoing.
    # One day, CC support.
    conversation = models.CharField(max_length=255, db_index=True, blank=True)
    is_personal = models.BooleanField(db_index=True)
    is_outgoing = models.BooleanField()

    uid = models.CharField(max_length=16)
    opcode = models.CharField(max_length=255, blank=True)

    signature = models.CharField(max_length=255)
    message = models.TextField()

    def __str__(self):
        return f'[{self.uid}] {self.class_key},{self.instance_key},{self.recipient if self.recipient else "*"}'

    @classmethod
    def from_notice(cls, notice, is_outgoing=False):
        # pylint: disable=too-many-statements
        # Further needed arguments: direction, user?

        def _d(octets: bytes) -> str:
            # pylint: disable=protected-access
            if notice._charset == b'UTF-8':
                return octets.decode('utf-8')
            if notice._charset == b'ISO-8859-1':
                return octets.decode('latin-1')
            for enc in ('ascii', 'utf-8', 'latin-1'):
                try:
                    return octets.decode(enc)
                except UnicodeDecodeError:
                    pass

        msg = cls()
        msg.zclass = _d(notice.cls)
        msg.zinstance = _d(notice.instance)
        msg.class_key = msg.zclass.casefold()
        msg.instance_key = msg.zinstance.casefold()
        msg.class_key_base = RE_BASE_STR.fullmatch(msg.class_key).group(1)
        msg.instance_key_base = RE_BASE_STR.fullmatch(msg.instance_key).group(1)
        msg.time = datetime.datetime.fromtimestamp(notice.time or notice.uid.time, datetime.timezone.utc)
        msg.auth = notice.auth
        msg.sender = _d(notice.sender)
        msg.recipient = _d(notice.recipient)

        msg.is_personal = bool(msg.recipient)
        msg.is_outgoing = is_outgoing
        if msg.is_personal:
            msg.conversation = msg.recipient if is_outgoing else msg.sender

        # Reconstruct the Zuid from its component parts and store it like roost would.
        uid = socket.inet_aton(notice.uid.address.decode('ascii'))
        uid_time = datetime.datetime.fromtimestamp(notice.uid.time, datetime.timezone.utc)
        uid += struct.pack('!II', int(uid_time.timestamp()), int(uid_time.microsecond))
        msg.uid = base64.b64encode(uid).decode('ascii')

        msg.opcode = _d(notice.opcode)

        def get_field(i):
            """Zephyr fields are one-indexed in formatting."""
            return _d(notice.fields[i-1])

        try:
            # Deal with well known weird format strings.
            if notice.format == (b'@center(@bold(NOC Message))\n\n@bold(Sender:) $1 <$sender>\n'
                                 b'@bold(Time:  ) $time\n\n@italic($opcode service on $instance $3.) $4\n'):
                # NOC messages are funny
                msg.message = (f'{msg.opcode} service on {msg.zinstance} {get_field(3)}\n'
                               f'{get_field(4)}')
            elif notice.format == b'New transaction [$1] entered in $2\nFrom: $3 ($5)\nSubject: $4':
                # Discuss messages are funny, 1 of 2
                msg.message = (f'New transaction [{get_field(1)}] entered in {get_field(2)}\n'
                               f'From: {get_field(3)} ({get_field(5)})\n'
                               f'Subject: {get_field(4)}')

            elif notice.format == b'New transaction [$1] entered in $2\nFrom: $3\nSubject: $4':
                # Discuss messages are funny, 2 of 2
                msg.message = (f'New transaction [{get_field(1)}] entered in {get_field(2)}\n'
                               f'From: {get_field(3)}\n'
                               f'Subject: {get_field(4)}')
            elif notice.format == b'MOIRA $instance on $fromhost:\n $message\n':
                # Moira messages are funny
                addr = notice.uid.address.decode('ascii')
                try:
                    hostname = socket.gethostbyaddr(addr)[0]
                except socket.herror:
                    hostname = addr
                msg.message = (f'MOIRA {msg.zinstance} on {hostname}:\n'
                               f' {get_field(1)}')
        except IndexError:
            pass

        if not msg.message:
            if len(notice.fields) == 2:
                msg.signature = get_field(1)[:255]
                msg.message = get_field(2)
            elif len(notice.fields) == 1:
                msg.message = get_field(1)
            else:
                # handle weird messages?
                msg.signature = get_field(1)[:255]
                msg.message = '\n'.join(get_field(i) for i in range(2,len(notice.fields)+1)).strip()

        return msg

    class Meta:
        index_together = [
            ['class_key', 'instance_key'],
            ['class_key_base', 'instance_key_base'],
        ]
        ordering = ['id']


class UserProcessState(models.Model):
    """This class will be used to persist data the user process needs. The
    `data` field format is defined by subscriber.py. This table is
    new to roost-ng and internal only, not to be exposed to clients.
    """

    user = models.OneToOneField('User', primary_key=True, on_delete=models.CASCADE, related_name='process_state')
    data = models.JSONField()


class ServerProcessState(models.Model):
    """This class will be used to persist data the server process needs. The
    `data` field format is defined by subscribers.py. This table is
    new to roost-ng and internal only, not to be exposed to clients.
    """

    data = models.JSONField()

    def save(self, *args, **kwargs):
        # pylint: disable=signature-differs
        self.__class__.objects.exclude(id=self.id).delete()
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        return cls.objects.last() or cls()
