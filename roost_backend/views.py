import datetime

from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.vary import vary_on_headers
import gssapi
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics, permissions, status

from . import filters, models, serializers


class AuthView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]
    serializer_class = serializers.AuthSerializer

    def handle_exception(self, exc):
        if isinstance(exc, gssapi.exceptions.GSSError):
            return Response(f'{type(exc).__name__}: {exc}', status=status.HTTP_400_BAD_REQUEST)
        return super().handle_exception(exc)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        server_creds = gssapi.Credentials(usage='accept')
        ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
        gss_token = ctx.step(serializer.validated_data['token'])

        if not ctx.complete:
            return Response("Roost-ng does not support multi-step GSS handshakes.", status=status.HTTP_400_BAD_REQUEST)

        principal = str(ctx.initiator_name)
        if serializer.validated_data['create_user']:
            user, _created = models.User.objects.get_or_create(principal=principal)
        else:
            user = models.User.objects.filter(principal=principal).first()

        if user is None:
            return Response({'user not registered': principal}, status=status.HTTP_401_UNAUTHORIZED)

        resp = self.serializer_class({
            'gss_token': gss_token,
            **user.get_auth_token_dict(),
        })
        return Response(resp.data)


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class PingView(APIView):
    def get(self, request):
        return Response({'pong': 1})


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
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


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class SubscriptionView(generics.ListAPIView):
    serializer_class = serializers.SubscriptionSerializer

    def get_queryset(self):
        return self.request.user.subscription_set


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class SubscribeView(APIView):
    serializer_class = serializers.SubscriptionSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, many=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        vdata = serializer.validated_data

        user = self.request.user
        subs = user.add_subscriptions(vdata)

        serializer = self.serializer_class(subs, many=True)
        return Response(serializer.data)


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class UnsubscribeView(APIView):
    serializer_class = serializers.SubscriptionSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        vdata = serializer.validated_data
        user = self.request.user
        sub, _removed = user.remove_subscription(vdata['zclass'], vdata['zinstance'], vdata['zrecipient'])

        serializer = self.serializer_class(sub)
        return Response(serializer.data)


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class MessageView(generics.ListAPIView):
    serializer_class = serializers.MessageSerializer

    def get_queryset(self):
        request = self.request
        qs = request.user.message_set.all()

        reverse = request.query_params.get('reverse', False)
        inclusive = request.query_params.get('inclusive', False)
        offset = request.query_params.get('offset')
        limit = int(request.query_params.get('limit', 0))

        # clamp limit
        if limit < 1:
            limit = 1
        elif limit > 100:
            limit = 100

        if offset:
            offset = int(offset)
            # TODO: seal/unseal offset
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


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
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


@method_decorator(vary_on_headers('Authorization'), name='dispatch')
class ZephyrCredsView(APIView):
    def get(self, request):
        # This should find out if we need to refresh the zephyr
        # credentials for this user and let them know. For now, the
        # answer is no, everything is fine.
        return Response({
            'needsRefresh': False,
        })

    def post(self, request):
        # Accept, validate, and then promptly ignore credentials.
        ret = request.zephyr_credentials is not None
        return Response({
            'refreshed': ret,
        })


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
# Stubbed:
# app.get('/v1/zephyrcreds', requireUser
# app.post('/v1/zephyrcreds', requireUser
# To do:
# app.post('/v1/zwrite', requireUser

# Also, a websocket at /v1/socket/websocket
# message types:
# - ping (-> pong)
# - new-tail
# - extend-tail
# - close-tail
