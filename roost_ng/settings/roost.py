from . import config

cfg = config.get_config_for_module(__name__)

ROOST_ALLOW_USER_CREATION = cfg.get('allow_user_creation', True)
ROOST_USER_CREATION_BLACKLIST = cfg.get('user_blacklist', [])
