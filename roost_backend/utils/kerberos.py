import base64
import ctypes
import logging
import os

import contrib.roost_python.krb5 as k5
import contrib.roost_python.krb5_ctypes as kc

_LOGGER = logging.getLogger(__name__)


def principal_to_group_name(princ, group_type):
    b64_principal = base64.b64encode(princ.encode("utf-8")).decode("ascii")
    return f'_{group_type}_PRINC_{b64_principal.strip("=")}'


def initialize_memory_ccache(principal=None):
    # Repoint to a new, in-memory credential cache.
    os.environ['KRB5CCNAME'] = 'MEMORY:'
    if principal:
        ctx = k5.Context()
        ccache = ctx.cc_default()
        ccache.init_name(principal)


def initialize_memory_ccache_from_client_keytab(reinit=False):
    # Repoint to a new, in-memory credential cache.
    os.environ['KRB5CCNAME'] = 'MEMORY:'
    ctx = k5.Context()
    ccache = ctx.cc_default()
    if reinit:
        ccache.destroy()
        ccache = ctx.cc_default()
    keytab = ctx.kt_client_default()
    ccache.init_from_keytab(keytab)


def add_credential_to_ccache(creds, princ=None):
    # pylint: disable=protected-access, too-many-locals, too-many-statements
    # all this should be abstracted away somewhere else.
    # This may be leaky. Consider kdestroy/re-init/re-ping zephyr servers.
    def json_name_bits_to_princ(ctx, realm, name):
        principal = ctx.build_principal(realm, name['name_string'])
        principal._handle.contents.type = name['name_type']
        return principal

    def flags_to_int(flags):
        assert len(flags) == 32
        assert set(flags).issubset({0, 1})
        ret = 0
        for flag in flags:
            ret = (ret << 1) | flag
        return ret

    def _b64(data):
        # b64decode strings, leave bytes alone
        if isinstance(data, str):
            return base64.b64decode(data)
        return data

    def verify_same_princ(client):
        if princ:
            client_name = client.unparse_name()
            given_client_name = princ.encode('utf-8')
            if client_name != given_client_name:
                raise ValueError(f'Ticket for wrong client: {client_name} vs {given_client_name}')

    ctx = k5.Context()
    ccache = ctx.cc_default()
    kcreds = kc.krb5_creds()
    kcreds.magic = -1760647408  # KV5M_PRINCIPAL

    # Extract and massage the principals
    server = json_name_bits_to_princ(ctx, creds['srealm'], creds['sname'])
    client = json_name_bits_to_princ(ctx, creds['crealm'], creds['cname'])
    verify_same_princ(client)

    tkt_server = json_name_bits_to_princ(ctx,
                                         creds['ticket']['realm'],
                                         creds['ticket']['sname'])
    kcreds.client = client._handle
    kcreds.server = server._handle

    # Prep the keyblock
    p_keyblock = kc.krb5_keyblock_ptr()
    key = creds['key']
    keydata = _b64(key['keyvalue'])
    kc.krb5_init_keyblock(ctx._handle, key['keytype'], len(keydata), ctypes.byref(p_keyblock))
    ctypes.memmove(p_keyblock.contents.contents, keydata, len(keydata))
    kcreds.keyblock = p_keyblock.contents

    # set the times
    kcreds.times.authtime = creds['authtime'] // 1000
    kcreds.times.starttime = creds['starttime'] // 1000
    kcreds.times.endtime = creds['endtime'] // 1000
    kcreds.times.renew_till = creds.get('renew_till', 0) // 1000
    kcreds.is_skey = False

    # This makes roost's python sad. Add a null check there before dereferencing.
    # Also, we're ignoring any addresses that may be in the tickets. Fix that.
    # kcreds.addresses = ctypes.POINTER(krb5_address_ptr)()

    # Parse the flags back into an int
    kcreds.ticket_flags = flags_to_int(creds['flags'])
    # Create a krb5_ticket...
    jtkt = creds['ticket']
    ktkt = kc.krb5_ticket()
    ktkt.magic = -1760647411  # KV5M_TICKET
    ktkt.server = tkt_server._handle
    ktkt.enc_part = kc.krb5_enc_data()
    ktkt.enc_part.magic = -1760647418  # KV5M_ENC_DATA
    ktkt.enc_part.enctype = jtkt['enc_part']['etype']
    ktkt.enc_part.kvno = jtkt['enc_part']['kvno']
    ktkt.enc_part.ciphertext = kc.krb5_data()
    ktkt.enc_part.ciphertext.magic = -1760647422  # KV5M_DATA
    tkt_ciphertext = _b64(jtkt['enc_part']['cipher'])
    ktkt.enc_part.ciphertext.length = len(tkt_ciphertext)
    ktkt.enc_part.ciphertext.data = (ctypes.c_char * len(tkt_ciphertext))(*tkt_ciphertext)

    # ...and be sad that we have to reach into krb5 internals to put it into the krb5_creds struct.
    p_tkt_data = kc.krb5_data_ptr()
    k5.encode_krb5_ticket(ctypes.byref(ktkt), ctypes.byref(p_tkt_data))
    kcreds.ticket = p_tkt_data.contents

    # compare against our current credential
    try:
        current_credential = _get_zephyr_creds(creds['ticket']['realm'])
        if current_credential.endtime >= kcreds.times.endtime:
            # New cred doesn't buy us any time; skip it.
            return
        k5.krb5_cc_remove_cred(ctx._handle, ccache._handle,
                               0, current_credential._handle)
    except k5.Error:
        # If this fails, we either don't have old credentials or the
        # MEMORY cache is too old to implement credential removal. In
        # the latter case, it's also old enough to store newer
        # credentials first, which probably works even if it is leaky.
        pass

    # and finally, store the new cred in the ccache.
    k5.krb5_cc_store_cred(ctx._handle, ccache._handle, kcreds)


def _get_zephyr_creds(realm):
    context = k5.Context()
    ccache = context.cc_default()
    principal = ccache.get_principal()
    zephyr = context.build_principal(realm, ['zephyr', 'zephyr'])
    return ccache.get_credentials(principal, zephyr)


def get_zephyr_creds_dict(realm):
    try:
        creds = _get_zephyr_creds(realm)
        creds_dict = creds.to_dict()
        return creds_dict
    except k5.Error:
        return {}


def have_valid_zephyr_creds(realm):
    try:
        creds = _get_zephyr_creds(realm)
        return creds.is_valid()
    except k5.Error:
        return False
