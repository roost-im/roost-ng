import base64
import datetime
import unittest

import contrib.roost_python.krb5 as k5
from roost_backend.utils import kerberos

# pylint: disable=protected-access


class KerberosTests(unittest.TestCase):
    realm = 'EXAMPLE.COM'
    client_princ = 'user@EXAMPLE.COM'
    server_princ = 'zephyr/zephyr@EXAMPLE.COM'

    def make_fake_cred(self, *, start=0, end=0):
        cname, crealm = self.client_princ.split('@', 1)
        sname, srealm = self.server_princ.split('@', 1)

        cred = {
            'crealm': crealm,
            'cname': {
                'name_type': 1,  # KRB5_NT_PRINCIPAL
                'name_string': list(cname.split('/'))
            },
            'ticket': {
                'tktVno': 5,
                'realm': srealm,
                'sname': {
                    'name_type': 0,  # KRB5_NT_UNKNOWN
                    'name_string': list(sname.split('/')),
                },
                'enc_part': {
                    'kvno': 1,
                    'etype': 18,
                    'cipher': base64.b64encode(b'notarealcipher'),
                },
            },
            'key': {
                'keytype': 18,
                'keyvalue': base64.b64encode(b'notarealkey'),
            },
            'flags': [int(i) for i in '0' * 32],
            'authtime': start * 1000,
            'starttime': start * 1000,
            'endtime': end * 1000,
            'srealm': srealm,
        }
        cred['sname'] = cred['ticket']['sname']
        return cred

    def test_kerberos_credential_pricipal_verification(self):
        kerberos.initialize_memory_ccache(self.client_princ)
        now = int(datetime.datetime.utcnow().timestamp())
        fake_cred = self.make_fake_cred(start=now-300, end=now+300)
        kerberos.add_credential_to_ccache(fake_cred, self.client_princ)

    def test_kerberos_credential_selection_old_first(self):
        kerberos.initialize_memory_ccache(self.client_princ)
        now = int(datetime.datetime.utcnow().timestamp())

        fake_cred1 = self.make_fake_cred(start=now-300, end=now+300)
        fake_cred2 = self.make_fake_cred(start=now-100, end=now+800)

        kerberos.add_credential_to_ccache(fake_cred1)
        kerberos.add_credential_to_ccache(fake_cred2)

        # Ensure we get the credentials that expire later.
        creds = kerberos._get_zephyr_creds(self.realm)
        self.assertEqual(creds._handle.contents.times.starttime,
                         fake_cred2['starttime'] // 1000)

    def test_kerberos_credential_selection_new_first(self):
        kerberos.initialize_memory_ccache(self.client_princ)
        now = int(datetime.datetime.utcnow().timestamp())

        fake_cred1 = self.make_fake_cred(start=now-300, end=now+300)
        fake_cred2 = self.make_fake_cred(start=now-100, end=now+800)

        kerberos.add_credential_to_ccache(fake_cred2)
        kerberos.add_credential_to_ccache(fake_cred1)

        # Ensure we get the credentials that expire later.
        creds = kerberos._get_zephyr_creds(self.realm)
        self.assertEqual(creds.endtime,
                         fake_cred2['endtime'] // 1000)

    def test_kerberos_credential_expired_cleanup(self):
        kerberos.initialize_memory_ccache(self.client_princ)
        now = int(datetime.datetime.utcnow().timestamp())
        ctx = k5.Context()
        ccache = ctx.cc_default()

        expired_cred = kerberos.parse_credential_dict(
            ctx, self.make_fake_cred(start=now-600, end=now-300))
        new_cred = self.make_fake_cred(start=now-100, end=now+800)

        self.assertEqual(len(ccache), 0)
        # Add manually since it's expired.
        k5.krb5_cc_store_cred(ctx._handle, ccache._handle, expired_cred._handle)
        self.assertEqual(len(ccache), 1)

        kerberos.add_credential_to_ccache(new_cred)
        self.assertEqual(len(ccache), 1)

    def test_kerberos_credential_properties(self):
        kerberos.initialize_memory_ccache(self.client_princ)
        now = int(datetime.datetime.utcnow().timestamp())
        ctx = k5.Context()
        start = now - 100
        end = now + 800
        cred = kerberos.parse_credential_dict(
            ctx, self.make_fake_cred(start=start, end=end))

        self.assertEqual(cred.client, self.client_princ.encode('utf8'))
        self.assertEqual(cred.server, self.server_princ.encode('utf8'))
        self.assertEqual(cred.starttime, start)
        self.assertEqual(cred.endtime, end)
