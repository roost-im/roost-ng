import hashlib
import uuid

from django.conf import settings

_BASE_KEY = hashlib.blake2s(settings.SECRET_KEY.encode('utf-8'), digest_size=16).digest()
def _secret_generator(context, as_uuid=False):
    """Derive secrets from SECRET_KEY and a context string"""
    ret = uuid.uuid5(uuid.UUID(bytes=_BASE_KEY), context)
    if as_uuid:
        return ret
    return str(ret)


AUTHTOKEN_KEY = _secret_generator('auth')
MESSGE_ID_SEALING_KEY = _secret_generator('msg.id', as_uuid=True).bytes
