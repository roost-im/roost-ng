import os

# TODO: parameterize this
DEFAULT_KRB5_KTNAME = '/etc/krb5.keytab.HTTP'
if DEFAULT_KRB5_KTNAME and not os.environ.get('KRB5_KTNAME'):
    os.environ['KRB5_KTNAME'] = DEFAULT_KRB5_KTNAME
