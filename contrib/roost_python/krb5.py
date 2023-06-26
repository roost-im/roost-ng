# Copyright (c) 2013 Massachusetts Institute of Technology
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# pylint: disable=consider-using-f-string, invalid-name, protected-access

import base64
import ctypes
import datetime
import functools

from . import krb5_ctypes


__all__ = ['Context']


class Error(Exception):
    def __init__(self, ctx_raw, code):
        self.code = code
        msg_c = krb5_ctypes.krb5_get_error_message(ctx_raw, code)
        self.message = msg_c.value.decode()
        krb5_ctypes.krb5_free_error_message(ctx_raw, msg_c)

    def __str__(self):
        return self.message


def check_error(fn):
    if fn.restype is not krb5_ctypes.krb5_error_code:
        return fn

    @functools.wraps(fn)
    def wrapped(ctx, *args):
        ret = fn(ctx, *args)
        if ret:
            raise Error(ctx, ret)
        return ret
    return wrapped


krb5_init_context = check_error(krb5_ctypes.krb5_init_context)
krb5_free_context = check_error(krb5_ctypes.krb5_free_context)
krb5_cc_initialize = check_error(krb5_ctypes.krb5_cc_initialize)
krb5_cc_default = check_error(krb5_ctypes.krb5_cc_default)
krb5_cc_close = check_error(krb5_ctypes.krb5_cc_close)
krb5_cc_destroy = check_error(krb5_ctypes.krb5_cc_destroy)
krb5_cc_get_principal = check_error(krb5_ctypes.krb5_cc_get_principal)
krb5_cc_store_cred = check_error(krb5_ctypes.krb5_cc_store_cred)
krb5_cc_remove_cred = check_error(krb5_ctypes.krb5_cc_remove_cred)
krb5_cc_start_seq_get = check_error(krb5_ctypes.krb5_cc_start_seq_get)
krb5_cc_next_cred = check_error(krb5_ctypes.krb5_cc_next_cred)
krb5_cc_end_seq_get = check_error(krb5_ctypes.krb5_cc_end_seq_get)
krb5_copy_creds = check_error(krb5_ctypes.krb5_copy_creds)
krb5_free_keytab_entry_contents = check_error(krb5_ctypes.krb5_free_keytab_entry_contents)
krb5_free_principal = check_error(krb5_ctypes.krb5_free_principal)
krb5_get_init_creds_keytab = check_error(krb5_ctypes.krb5_get_init_creds_keytab)
krb5_kt_client_default = check_error(krb5_ctypes.krb5_kt_client_default)
krb5_kt_default = check_error(krb5_ctypes.krb5_kt_default)
krb5_kt_start_seq_get = check_error(krb5_ctypes.krb5_kt_start_seq_get)
krb5_kt_next_entry = check_error(krb5_ctypes.krb5_kt_next_entry)
krb5_kt_end_seq_get = check_error(krb5_ctypes.krb5_kt_end_seq_get)
krb5_kt_close = check_error(krb5_ctypes.krb5_kt_close)
krb5_unparse_name = check_error(krb5_ctypes.krb5_unparse_name)
krb5_free_unparsed_name = check_error(krb5_ctypes.krb5_free_unparsed_name)
krb5_build_principal = check_error(krb5_ctypes.krb5_build_principal)
krb5_parse_name = check_error(krb5_ctypes.krb5_parse_name)
krb5_get_credentials = check_error(krb5_ctypes.krb5_get_credentials)
krb5_free_creds = check_error(krb5_ctypes.krb5_free_creds)
krb5_free_ticket = check_error(krb5_ctypes.krb5_free_ticket)
krb5_init_keyblock = check_error(krb5_ctypes.krb5_init_keyblock)
krb5_get_init_creds_opt_alloc = check_error(krb5_ctypes.krb5_get_init_creds_opt_alloc)
krb5_get_init_creds_opt_free = check_error(krb5_ctypes.krb5_get_init_creds_opt_free)
encode_krb5_ticket = check_error(krb5_ctypes.encode_krb5_ticket)


# This one is weird and takes no context. But the free function does??
def krb5_decode_ticket(*args):
    ret = krb5_ctypes.krb5_decode_ticket(*args)
    if ret:
        raise Error(krb5_ctypes.krb5_context(), ret)
    return ret


def to_str(s):
    if isinstance(s, str):
        return s.encode('utf-8')
    return s


class Context:
    def __init__(self):
        self._handle = krb5_ctypes.krb5_context()
        krb5_init_context(self._handle)

    def __del__(self):
        if bool(self._handle):
            krb5_free_context(self._handle)

    def cc_default(self):
        ccache = CCache(self)
        krb5_cc_default(self._handle, ccache._handle)
        return ccache

    def kt_client_default(self):
        keytab = Keytab(self)
        krb5_kt_client_default(self._handle, keytab._handle)
        return keytab

    def kt_default(self):
        keytab = Keytab(self)
        krb5_kt_default(self._handle, keytab._handle)
        return keytab

    def build_principal(self, realm, name):
        realm = to_str(realm)
        name = [to_str(comp) for comp in name]
        principal = Principal(self)
        name_args = [ctypes.c_char_p(comp) for comp in name]
        name_args.append(ctypes.c_char_p())
        krb5_build_principal(self._handle,
                             principal._handle,
                             len(realm),
                             ctypes.c_char_p(realm),
                             *name_args)
        return principal

    def parse_name(self, name):
        return Principal(self, name)

    def decode_ticket(self, data):
        data = to_str(data)
        data_c = krb5_ctypes.krb5_data()
        # Why do I need this dance...
        data_c.data = ctypes.cast(
            ctypes.c_char_p(data),
            ctypes.POINTER(ctypes.c_char))
        data_c.length = len(data)
        return self._decode_ticket(data_c)

    def _decode_ticket(self, data_c):
        ticket = Ticket(self)
        krb5_decode_ticket(data_c, ticket._handle)
        return ticket


class CCache:
    class Iterator:
        # Underlying iterator behavior is undefined if the ccache is
        # modified while iterating. Consider also importing
        # krb5_cc_lock and krb5_cc_unlock.
        def __init__(self, ccache):
            self.ccache = ccache
            self.cursor = krb5_ctypes.krb5_cc_cursor()
            krb5_cc_start_seq_get(self.ctx._handle,
                                  self.ccache._handle,
                                  self.cursor)

        def __del__(self):
            if self.cursor:
                krb5_cc_end_seq_get(self.ctx._handle,
                                    self.ccache._handle,
                                    self.cursor)

        def __next__(self):
            cred = krb5_ctypes.krb5_creds()
            try:
                krb5_cc_next_cred(self.ctx._handle,
                                  self.ccache._handle,
                                  self.cursor,
                                  cred)
            except Error as e:
                krb5_cc_end_seq_get(self.ctx._handle,
                                    self.ccache._handle,
                                    self.cursor)
                self.cursor = None
                raise StopIteration from e
            ret = Credentials(self.ctx)
            krb5_copy_creds(self.ctx._handle, cred, ret._handle)
            return ret

        @property
        def ctx(self):
            return self.ccache._ctx

    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_ccache()

    def __del__(self):
        if bool(self._handle):
            krb5_cc_close(self._ctx._handle, self._handle)

    def __iter__(self):
        return self.Iterator(self)

    def __len__(self):
        ret = 0
        for _ in self:
            ret += 1
        return ret

    def init_name(self, princ):
        if isinstance(princ, (str, bytes)):
            princ = self._ctx.parse_name(princ)
        krb5_cc_initialize(
            self._ctx._handle,
            self._handle,
            princ._handle)

    def init_from_keytab(self, keytab, service=None):
        creds = krb5_ctypes.krb5_creds()

        client_principal = keytab.get_first_principal()
        options = krb5_ctypes.krb5_get_init_creds_opt()
        krb5_get_init_creds_opt_alloc(self._ctx._handle, options)
        self.init_name(client_principal)
        if isinstance(service, str):
            service = service.encode()
        elif isinstance(service, Principal):
            service = service.unparse_name()
        krb5_get_init_creds_keytab(self._ctx._handle,
                                   creds,
                                   client_principal._handle,
                                   keytab._handle,
                                   0,
                                   service,
                                   options)
        krb5_cc_store_cred(self._ctx._handle, self._handle, creds)
        krb5_get_init_creds_opt_free(self._ctx._handle, options)

    def get_principal(self):
        principal = Principal(self._ctx)
        krb5_cc_get_principal(self._ctx._handle,
                              self._handle,
                              principal._handle)
        return principal

    def get_credentials(self, client, server,
                        cache_only=False,
                        user_to_user=False):
        flags = 0
        if cache_only:
            flags |= krb5_ctypes.KRB5_GC_CACHED
        if user_to_user:
            flags |= krb5_ctypes.KRB5_GC_USER_USER

        in_creds = krb5_ctypes.krb5_creds()
        in_creds.client = client._handle
        in_creds.server = server._handle
        # TODO(davidben): If we care, pass in parameters for the other
        # options too.
        creds = Credentials(self._ctx)
        krb5_get_credentials(self._ctx._handle, flags, self._handle, in_creds,
                             creds._handle)
        return creds

    def destroy(self):
        krb5_cc_destroy(self._ctx._handle, self._handle)
        self._handle = None


class Keytab:
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_keytab()

    def __del__(self):
        if bool(self._handle):
            krb5_kt_close(self._ctx._handle, self._handle)

    def get_entries(self, cnt=0):
        cur = krb5_ctypes.krb5_kt_cursor()
        ret = []
        krb5_kt_start_seq_get(self._ctx._handle, self._handle, cur)
        while True:
            entry = KeytabEntry(self._ctx)
            try:
                krb5_kt_next_entry(self._ctx._handle, self._handle, entry._handle, cur)
            except Error:
                break
            ret.append(entry)
            if cnt and len(ret) == cnt:
                break
        krb5_kt_end_seq_get(self._ctx._handle, self._handle, cur)
        return ret

    def get_first_entry(self):
        return self.get_entries(cnt=1)[0]

    def get_first_principal(self):
        return self.get_first_entry().principal()


class KeytabEntry:
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_keytab_entry()

    def __del__(self):
        if bool(self._handle):
            krb5_free_keytab_entry_contents(self._ctx._handle, self._handle)

    def unparse_name(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle.principal, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    def principal(self):
        return Principal(self._ctx, princ_str=self.unparse_name())

    def __str__(self):
        return self.unparse_name().decode()  # pylint: disable=no-member

    def __repr__(self):
        return '<%s: %s (kvno: %i)>' % (self.__class__.__name__, self.unparse_name(), self._handle.vno)


class Principal:
    def __init__(self, ctx, princ_str=None):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_principal()
        if princ_str:
            princ = None
            if isinstance(princ_str, bytes):
                princ = princ_str
            elif isinstance(princ_str, str):
                princ = princ_str.encode()
            if princ:
                krb5_parse_name(ctx._handle, princ, self._handle)

    def __del__(self):
        if bool(self._handle):
            krb5_free_principal(self._ctx._handle, self._handle)

    def unparse_name(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    def __str__(self):
        return self.unparse_name().decode()  # pylint: disable=no-member

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.unparse_name())


class Credentials:
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_creds_ptr()

    def __del__(self):
        if bool(self._handle):
            krb5_free_creds(self._ctx._handle, self._handle)

    def copy_from_cstruct(self, cred):
        krb5_copy_creds(self._ctx._handle, cred, self._handle)
        return self

    def decode_ticket(self):
        return self._ctx._decode_ticket(self._handle.contents.ticket)

    def decode_second_ticket(self):
        return self._ctx._decode_second_ticket(
            self._handle.contents.second_ticket)

    @property
    def starttime(self):
        return self._handle.contents.times.starttime

    @property
    def endtime(self):
        return self._handle.contents.times.endtime

    @property
    def client(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle.contents.client, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    @property
    def server(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle.contents.server, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    def is_valid(self):
        """Chceks to see if the credential is in its valid lifetime."""
        now = datetime.datetime.utcnow().timestamp()
        return self.starttime <= now < self.endtime

    def to_dict(self):
        # TODO(davidben): More sensible would be to put this format
        # into roost.py and expose all the attributes in the public
        # API. But whatever.
        ret = {}
        client_data = self._handle.contents.client.contents
        ret['crealm'] = client_data.realm.as_str().decode('utf-8')
        ret['cname'] = {
            'nameType': client_data.type,
            'nameString': [client_data.data[i].as_str().decode('utf-8')
                           for i in range(client_data.length)],
            }
        ret['ticket'] = self.decode_ticket().to_dict()
        keyblock = self._handle.contents.keyblock
        ret['key'] = {
            'keytype': keyblock.enctype,
            'keyvalue': base64.b64encode(
                keyblock.contents_as_str()).decode('ascii')
        }
        flags = self._handle.contents.ticket_flags
        ret['flags'] = [(1 if (flags & (1 << (31 - i))) else 0)
                        for i in range(32)]
        # Webathena times are milliseconds, Kerberos uses seconds
        ret['authtime'] = self._handle.contents.times.authtime * 1000
        if self._handle.contents.times.starttime:
            ret['starttime'] = self._handle.contents.times.starttime * 1000
        ret['endtime'] = self._handle.contents.times.endtime * 1000
        if self._handle.contents.times.renew_till:
            ret['renewTill'] = self._handle.contents.times.renew_till * 1000
        server_data = self._handle.contents.server.contents
        ret['srealm'] = server_data.realm.as_str().decode('utf-8')
        ret['sname'] = {
            'nameType': server_data.type,
            'nameString': [server_data.data[i].as_str().decode('utf-8')
                           for i in range(server_data.length)],
            }
        addrs = []
        i = 0
        if bool(self._handle.contents.addresses):
            while bool(self._handle.contents.addresses[i]):
                addr = self._handle.contents.addresses[i].contents
                addrs.append({
                    'addrType': addr.addrtype,
                    'address': addr.contents_as_str()
                })
                i += 1
        if addrs:
            ret['caddr'] = addrs

        return ret


class Ticket:
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_ticket_ptr()

    def __del__(self):
        if bool(self._handle):
            krb5_free_ticket(self._ctx._handle, self._handle)

    def to_dict(self):
        ret = {}
        ret['tktVno'] = 5
        server_data = self._handle.contents.server.contents
        ret['realm'] = server_data.realm.as_str().decode('utf-8')
        ret['sname'] = {
            'nameType': server_data.type,
            'nameString': [server_data.data[i].as_str().decode('utf-8')
                           for i in range(server_data.length)],
            }
        ret['encPart'] = {
            'kvno': self._handle.contents.enc_part.kvno,
            'etype': self._handle.contents.enc_part.enctype,
            'cipher': base64.b64encode(
                self._handle.contents.enc_part.ciphertext.as_str()).decode('ascii'),
        }
        return ret
