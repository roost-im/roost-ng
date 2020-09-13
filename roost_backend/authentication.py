from types import MappingProxyType

from rest_framework import authentication, exceptions
import jwt

from . import models, serializers, secrets


class JWTAuthentication(authentication.TokenAuthentication):
    keyword = 'Bearer'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = None
        self.claims = None

    def authenticate(self, request):
        self.request = request
        self.request.zephyr_credentials = None
        return super().authenticate(request)

    @staticmethod
    def _decode_token(token):
        try:
            return jwt.decode(token, secrets.AUTHTOKEN_KEY, algorithms=['HS256'])
        except jwt.DecodeError:
            return None
        except jwt.ExpiredSignature as exc:
            raise exceptions.AuthenticationFailed('Expired token') from exc
        except jwt.InvalidAudience as exc:
            raise exceptions.AuthenticationFailed('Invalid token') from exc

    @classmethod
    def validate_token(cls, token, raise_on_jwt_error=True):
        try:
            claims = cls._decode_token(token)
        except jwt.exceptions.InvalidTokenError:
            if raise_on_jwt_error:
                raise
            claims = None
        if claims is None:
            return None, None

        if 'identity' in claims:
            user = models.User.objects.filter(**claims['identity']).first()
        return claims, user

    def authenticate_credentials(self, key):
        claims, user = self.validate_token(key)
        if claims is None:
            # JWT did not parse; allow other authentication schemes to be tried, if any.
            return None

        # Check for and extract zephyr credentials that may be coming in with the payload.
        if 'credentials' in self.request.data:
            serializer = serializers.KerberosCredentialsSerializer(data=self.request.data['credentials'],
                                                                   context={'user': user})
            if serializer.is_valid():
                self.request.zephyr_credentials = serializer.validated_data
                del self.request.data['credentials']
                user.send_to_user_subscriber({
                    'type': 'inject_credentials',
                    'creds': serializer.validated_data,
                })

        if user:
            return (user, MappingProxyType(claims))
        raise exceptions.AuthenticationFailed('User inactive or deleted')
