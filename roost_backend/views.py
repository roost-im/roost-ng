import datetime

from asgiref.sync import async_to_sync
import channels.layers
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.vary import vary_on_headers
import gssapi
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics, permissions, status

from . import filters, models, serializers, utils

COMMON_DECORATORS = [vary_on_headers('Authorization'), never_cache]


@method_decorator(never_cache, name='dispatch')
class AuthView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    serializer_class = serializers.AuthSerializer

    def handle_exception(self, exc):
        if isinstance(exc, gssapi.exceptions.GSSError):
            return Response(f'{type(exc).__name__}: {exc}', status=status.HTTP_400_BAD_REQUEST)
        return super().handle_exception(exc)

    @staticmethod
    async def wait_for_user_process(principal):
        channel_layer = channels.layers.get_channel_layer()
        channel_name = utils.principal_to_user_subscriber_announce_channel(principal)

        while True:
            message = await channel_layer.receive(channel_name)
            if message.get('principal') == principal:
                return

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        server_creds = gssapi.Credentials(usage='accept')
        ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
        gss_token = ctx.step(serializer.validated_data['token'])

        if not ctx.complete:
            return Response("Roost-ng does not support multi-step GSS handshakes.", status=status.HTTP_400_BAD_REQUEST)

        principal = str(ctx.initiator_name)
        if (serializer.validated_data['create_user']
                and settings.ROOST_ALLOW_USER_CREATION
                and principal not in settings.ROOST_USER_CREATION_BLACKLIST):
            with transaction.atomic():
                user, created = models.User.objects.get_or_create(principal=principal)
            if created:
                async_to_sync(self.wait_for_user_process)(user.principal)
        else:
            user = models.User.objects.filter(principal=principal).first()

        if user is None:
            return HttpResponse('User does not exist', status=status.HTTP_403_FORBIDDEN)

        resp = self.serializer_class({
            'gss_token': gss_token,
            **user.get_auth_token_dict(),
        })
        return Response(resp.data)


@method_decorator(COMMON_DECORATORS, name='dispatch')
class PingView(APIView):
    def get(self, request):
        return Response({'pong': 1})


@method_decorator(COMMON_DECORATORS, name='dispatch')
class InfoView(APIView):
    serializer_class = serializers.InfoSerializer

    def get(self, request):
        serializer = self.serializer_class(self.request.user)
        return Response(serializer.data)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        vdata = serializer.validated_data

        updated = False
        with transaction.atomic():
            user = models.User.objects.select_for_update().filter(pk=self.request.user.pk).first()
            if user.info_version == vdata['expected_version']:
                user.info_version += 1
                user.info = vdata['info']
                user.save()
                updated = True

        if updated:
            return Response({'updated': True})
        return Response({'updated': False, **self.serializer_class(user).data})


@method_decorator(COMMON_DECORATORS, name='dispatch')
class SubscriptionView(generics.ListAPIView):
    serializer_class = serializers.SubscriptionSerializer

    def get_queryset(self):
        return self.request.user.subscription_set


@method_decorator(COMMON_DECORATORS, name='dispatch')
class SubscribeView(APIView):
    serializer_class = serializers.SubscriptionSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data['subscriptions'], many=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        vdata = serializer.validated_data

        user = self.request.user
        subs = user.add_subscriptions(vdata)

        serializer = self.serializer_class(subs, many=True)
        return Response(serializer.data)


@method_decorator(COMMON_DECORATORS, name='dispatch')
class UnsubscribeView(APIView):
    serializer_class = serializers.SubscriptionSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data['subscription'])
        serializer.is_valid(raise_exception=True)
        vdata = serializer.validated_data
        user = self.request.user
        sub, _removed = user.remove_subscription(vdata['zclass'], vdata['zinstance'], vdata['zrecipient'])

        serializer = self.serializer_class(sub)
        return Response(serializer.data)


@method_decorator(COMMON_DECORATORS, name='dispatch')
class MessageView(generics.ListAPIView):
    serializer_class = serializers.MessageSerializer

    def get_queryset(self):
        request = self.request
        qs = request.user.message_set.all()

        reverse = int(request.query_params.get('reverse', False))
        inclusive = int(request.query_params.get('inclusive', False))
        offset = request.query_params.get('offset')
        limit = int(request.query_params.get('count', 0))

        # clamp limit
        if limit < 1:
            limit = 1
        elif limit > 128:
            limit = 128

        if offset:
            offset = utils.unseal_message_id(offset)
            # TODO: Double check this
            if inclusive and reverse:
                qs = qs.filter(id__lte=offset)
            elif inclusive:
                qs = qs.filter(id__gte=offset)
            elif reverse:
                qs = qs.filter(id__lt=offset)
            else:
                qs = qs.filter(id__gt=offset)

        if reverse:
            qs = qs.reverse()

        qs = filters.MessageFilter(**request.query_params).apply_to_queryset(qs)
        return qs[:limit]

    def list(self, request, *args, **kwargs):
        return Response({
            'messages': self.serializer_class(self.get_queryset(), many=True).data,
            'isDone': True,
        })


@method_decorator(COMMON_DECORATORS, name='dispatch')
class MessageByTimeView(APIView):
    def get(self, request):
        time = request.query_params.get('time')
        if time is None:
            return Response('time not specified', status=status.HTTP_400_BAD_REQUEST)
        time = datetime.datetime.fromtimestamp(int(time) / 1000, datetime.timezone.utc)
        msg = request.user.message_set.filter(receive_time__gte=time).order_by('receive_time').first()
        return Response({
            'id': msg and msg.id
        })


@method_decorator(COMMON_DECORATORS, name='dispatch')
class ZephyrCredsView(APIView):
    def get(self, request):
        response = request.user.send_to_user_subscriber({
            'type': 'have_valid_credentials',
        }, wait_for_response=True)

        return Response({
            'needsRefresh': not response['valid'],
        })

    def post(self, request):
        # Accept, validate, and then promptly ignore credentials.
        # If they were included, they auth layer pushed them to the user process.
        ret = request.zephyr_credentials is not None
        return Response({
            'refreshed': ret,
        })


@method_decorator(COMMON_DECORATORS, name='dispatch')
class ZWriteView(APIView):
    serializer_class = serializers.OutgoingMessageSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data['message'])
        serializer.is_valid(raise_exception=True)
        response = request.user.send_to_user_subscriber({
            'type': 'zwrite',
            'message': serializer.validated_data,
        }, wait_for_response=True)
        return Response(response)


# Roost's endpoints:
# Done:
# app.post('/v1/auth
# app.get('/v1/ping', requireUser
# app.get('/v1/info', requireUser
# app.post('/v1/info', requireUser
# app.get('/v1/subscriptions', requireUser
# app.post('/v1/subscribe', requireUser
# app.post('/v1/unsubscribe', requireUser
# app.get('/v1/messages', requireUser
# app.get('/v1/bytime', requireUser
# app.post('/v1/zwrite', requireUser
# app.get('/v1/zephyrcreds', requireUser
# app.post('/v1/zephyrcreds', requireUser

# Also, a websocket at /v1/socket/websocket
# message types:
# - ping (-> pong)
# - new-tail
# - extend-tail
# - close-tail
