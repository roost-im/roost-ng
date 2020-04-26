import datetime

from django.conf import settings
from django.db import models, transaction
import jwt

from . import secrets


class User(models.Model):
    principal = models.CharField(max_length=255, unique=True)
    info = models.TextField(default='{}')
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
        if recipient == '*':
            recipient = ''
        if recipient not in (self.principal, ''):
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
    auth = models.BooleanField()  # was the zgram authentic?
    auth_checked = models.BooleanField()  # were we able to confirm it was authentic?
    sender = models.CharField(max_length=255, db_index=True)
    recipient = models.CharField(max_length=255, db_index=True, blank=True)

    # empty for non-personals; sender for incoming, recipient for outgoing.
    # One day, CC support.
    conversation = models.CharField(max_length=255, db_index=True, blank=True)
    is_personal = models.BooleanField(db_index=True)
    is_outgoing = models.BooleanField()

    uid = models.BinaryField(max_length=16)
    opcode = models.CharField(max_length=255, blank=True)

    signature = models.CharField(max_length=255)
    message = models.BinaryField()

    class Meta:
        index_together = [
            ['class_key', 'instance_key'],
            ['class_key_base', 'instance_key_base'],
        ]
        ordering = ['id']
