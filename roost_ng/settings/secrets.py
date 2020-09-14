from . import config

# SECURITY WARNING: keep the secret key used in production secret!
# TODO: load SECRET_KEY from non-repo store.
# This is an obviously awful bad key.
cfg = config.get_config_for_module(__name__)
SECRET_KEY = cfg.get('secret_key', '00000000000000000000000000000000000000000000000000')
