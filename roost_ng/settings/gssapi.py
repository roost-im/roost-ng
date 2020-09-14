import os

from . import config
gssapi_config = config.get_config_for_module(__name__)

# This keytab is used when talking to the API.
DEFAULT_KRB5_KTNAME = gssapi_config.get('server_keytab', '/etc/krb5.keytab.HTTP')

# This keytab is used by the subscriber when talking to a zephyrd.
DEFAULT_SUBSCRIBER_KRB5_KEYTAB = gssapi_config.get('client_keytab', '/etc/krb5.keytab.daemon')

if DEFAULT_KRB5_KTNAME and not os.environ.get('KRB5_KTNAME'):
    os.environ['KRB5_KTNAME'] = DEFAULT_KRB5_KTNAME

if DEFAULT_SUBSCRIBER_KRB5_KEYTAB and not os.environ.get('KRB5_CLIENT_KTNAME'):
    os.environ['KRB5_CLIENT_KTNAME'] = DEFAULT_SUBSCRIBER_KRB5_KEYTAB
