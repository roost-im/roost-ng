import os

# TODO: parameterize this
# This keytab is used when talking to the API.
DEFAULT_KRB5_KTNAME = '/etc/krb5.keytab.HTTP'

# This keytab is used by the subscriber when talking to a zephyrd.
DEFAULT_SUBSCRIBER_KRB5_KEYTAB = '/etc/krb5.keytab.daemon'

if DEFAULT_KRB5_KTNAME and not os.environ.get('KRB5_KTNAME'):
    os.environ['KRB5_KTNAME'] = DEFAULT_KRB5_KTNAME

if DEFAULT_SUBSCRIBER_KRB5_KEYTAB and not os.environ.get('KRB5_CLIENT_KTNAME'):
    os.environ['KRB5_CLIENT_KTNAME'] = DEFAULT_SUBSCRIBER_KRB5_KEYTAB
