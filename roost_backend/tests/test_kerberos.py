import base64
import datetime

from django.test import TestCase

from roost_backend.utils import kerberos


class KerberosTests(TestCase):
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
