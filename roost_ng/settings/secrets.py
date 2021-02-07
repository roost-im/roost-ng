import os.path

from . import config

# Set the Django SECRET_KEY, and potentially other secrets
#
# If /etc/roost-ng/django-SECRET_KEY exists, the entire contents will
# be used as the key.

# To take that approach, here's a one-liner you can use to initialize it:
# python3 -c "import secrets; open('/etc/roost-ng/django-SECRET_KEY', 'w').write(secrets.token_urlsafe(50))

# Otherwise, the SECRET_KEY will be fetched from /etc/roost-ng/config.yml if it's
# set there, or otherwise use all-zeroes.

# SECURITY WARNING: keep the secret key used in production secret!
# TODO: load SECRET_KEY from non-repo store.
# This is an obviously awful bad key.

SECRET_KEY_FILE = '/etc/roost-ng/django-SECRET_KEY'
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as secret_key_file:
        SECRET_KEY = secret_key_file.read()
else:
    cfg = config.get_config_for_module(__name__)
    SECRET_KEY = cfg.get('secret_key', '00000000000000000000000000000000000000000000000000')
