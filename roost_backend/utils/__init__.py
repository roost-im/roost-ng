import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import kerberos
from ..secrets import MESSGE_ID_SEALING_KEY


def principal_to_user_process_group_name(princ):
    return kerberos.principal_to_group_name(princ, 'UP')


def principal_to_user_socket_group_name(princ):
    return kerberos.principal_to_group_name(princ, 'WS')


# Yes, for sealing and unsealing we are using AES in ECB mode.
# Yes, this is exactly what we want.
# id -> consistent UUID, and back again

# Quoting the original roost codebase on this topic (lib/msgid.js):
# Yeah, yeah, ad-hoc crypto... this is not particularly
# important. Just a way to give us opaque message ids without having
# to actually maintain state, and the only purpose of opaque message
# ids is to not trivially reveal how many messages you can't see.

def seal_message_id(msg_id: int) -> uuid.UUID:
    cipher = Cipher(algorithms.AES(MESSGE_ID_SEALING_KEY), modes.ECB())
    enc = cipher.encryptor()
    cbytes = enc.update(msg_id.to_bytes(16, 'big')) + enc.finalize()
    return uuid.UUID(bytes=cbytes)


def unseal_message_id(sealed_msg_id: uuid.UUID) -> int:
    cipher = Cipher(algorithms.AES(MESSGE_ID_SEALING_KEY), modes.ECB())
    dec = cipher.decryptor()
    pbytes = dec.update(sealed_msg_id.bytes) + dec.finalize()
    return int.from_bytes(pbytes, 'big')
