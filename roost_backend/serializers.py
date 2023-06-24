import binascii
import base64
import datetime

from rest_framework import serializers

from . import models, utils

# pylint: disable=abstract-method
# pylint complains about missing optional `create` and `update` methods in
# a bunch of serializers


# Custom Fields
class Base64Field(serializers.Field):
    def to_representation(self, value: bytes) -> str:
        return base64.b64encode(value).decode('ascii')

    def to_internal_value(self, data: str) -> bytes:
        try:
            return base64.b64decode(data)
        except binascii.Error as exc:
            raise serializers.ValidationError(str(exc))


class DateTimeAsMillisecondsField(serializers.Field):
    def to_representation(self, value):
        return value.timestamp() * 1000

    def to_internal_value(self, data):
        return datetime.datetime.fromtimestamp(data/1000, datetime.timezone.utc)


class SealedMessageIdField(serializers.UUIDField):
    def to_representation(self, value):
        return super().to_representation(utils.seal_message_id(value))

    def to_internal_value(self, data):
        return utils.unseal_message_id(super().to_internal_value(data))


# Kerberos Credential Serializers
class _InlineNameSerializer(serializers.Serializer):
    name_type = serializers.IntegerField()
    name_string = serializers.ListField(child=serializers.CharField())


class _InlineEncPartSerializer(serializers.Serializer):
    kvno = serializers.IntegerField()
    etype = serializers.IntegerField()
    cipher = Base64Field()


class _InlineTicketSerializer(serializers.Serializer):
    tkt_vno = serializers.IntegerField()
    realm = serializers.CharField()
    sname = _InlineNameSerializer()
    enc_part = _InlineEncPartSerializer()


class _InlineKeySerializer(serializers.Serializer):
    keytype = serializers.IntegerField()
    keyvalue = Base64Field()


class KerberosCredentialsSerializer(serializers.Serializer):
    crealm = serializers.CharField()
    cname = _InlineNameSerializer()
    ticket = _InlineTicketSerializer()
    key = _InlineKeySerializer()
    flags = serializers.ListField(child=serializers.BooleanField())
    # These times are in ms since epoch
    authtime = serializers.IntegerField()
    starttime = serializers.IntegerField()
    endtime = serializers.IntegerField()
    renew_till = serializers.IntegerField(required=False, default=0)
    srealm = serializers.CharField()
    sname = _InlineNameSerializer()

    # Validate that the ticket appears to be for the user if we have one.
    # This can probably be done better, but it'll do for now.
    def validate_crealm(self, value):
        context = getattr(self, 'context', {})
        request = user = None
        if 'user' in context:
            user = context['user']
        elif 'request' in context:
            request = context['request']
            user = request and request.user
        if user:
            realm = user.principal.split('@')[1]
            if value != realm:
                raise ValueError(f'Unexpected realm [{value}] for user [{user.principal}]')
        return value

    def validate_cname(self, value):
        context = getattr(self, 'context', {})
        request = user = None
        if 'user' in context:
            user = context['user']
        elif 'request' in context:
            request = context['request']
            user = request and request.user
        if user:
            names = user.principal.split('@')[0].split('/')
            if value['name_string'] != names:
                raise ValueError(f'Unexpected names [{value}] for user [{user.principal}]')
        return value


# View Serializers
class AuthSerializer(serializers.Serializer):
    # This would be used for fake-auth, which we are not supporting yet.
    # principal = serializers.CharField(max_length=255, required=False, write_only=True)
    token = Base64Field(required=True, write_only=True)
    create_user = serializers.BooleanField(write_only=True, label='Create user?', required=False, default=False)
    gss_token = Base64Field(read_only=True)
    auth_token = serializers.CharField(read_only=True)
    expires = serializers.IntegerField(read_only=True)


class InfoSerializer(serializers.ModelSerializer):
    # Translate info_version to match Roost API
    version = serializers.IntegerField(source='info_version', read_only=True)

    # These are used in the POST request/response
    expected_version = serializers.IntegerField(write_only=True, required=True)

    class Meta:
        model = models.User
        fields = ['info', 'version', 'expected_version']


class SubscriptionSerializer(serializers.ModelSerializer):
    instance = serializers.CharField(source='zinstance')
    recipient = serializers.CharField(source='zrecipient', allow_blank=True)
    # credentials = KerberosCredentialsSerializer(required=False, write_only=True)

    def validate_recipient(self, value):
        request = getattr(self, 'context', {}).get('request')
        if request and request.user:
            if not any([value in ('', '*', request.user.principal),
                        value.startswith('@'),
                        value.startswith('*@'),
                        value.lower() == '%me%']):
                raise serializers.ValidationError(
                    f'Invalid recipient [{value}] for subscription by user [{request.user.principal}]')
        return value

    class Meta:
        model = models.Subscription
        fields = ['class', 'class_key', 'instance', 'instance_key', 'recipient']
        extra_kwargs = {
            'class_key': {'read_only': True},
            'instance_key': {'read_only': True},
        }


# class is a reserved word, so let's do this the hard way.
# pylint: disable=no-member, protected-access
SubscriptionSerializer._declared_fields['class'] = serializers.CharField(source='zclass')
# pylint: enable=no-member, protected-access


class MessageSerializer(serializers.ModelSerializer):
    id = SealedMessageIdField()
    time = DateTimeAsMillisecondsField()
    receive_time = DateTimeAsMillisecondsField()
    # message = serializers.SerializerMethodField()
    instance = serializers.CharField(source='zinstance')

    # @staticmethod
    # def get_message(obj):
    #     return obj.message.decode('utf-8')

    class Meta:
        model = models.Message
        exclude = ['users', 'zclass', 'zinstance']


# class is a reserved word, so let's do this the hard way.
# pylint: disable=no-member, protected-access
MessageSerializer._declared_fields['class'] = serializers.CharField(source='zclass')
# pylint: enable=no-member, protected-access


class OutgoingMessageSerializer(serializers.Serializer):
    instance = serializers.CharField(allow_blank=True)
    recipient = serializers.CharField(allow_blank=True)
    opcode = serializers.CharField(default='', allow_blank=True)
    signature = serializers.CharField(default='', allow_blank=True)
    message = serializers.CharField(allow_blank=True)


# class is a reserved word, so let's do this the hard way.
# pylint: disable=no-member, protected-access
OutgoingMessageSerializer._declared_fields['class'] = serializers.CharField()
# pylint: enable=no-member, protected-access
