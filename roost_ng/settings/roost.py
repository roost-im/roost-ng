from . import config

cfg = config.get_config_for_module(__name__)


# This should be either a boolean or a list of allowed principals.
ROOST_ALLOW_USER_CREATION = cfg.get('allow_user_creation', False)

# A list of forbidden principals, used if ROOST_ALLOW_USER_CREATION is True.
# This list is ignored if ROOST_ALLOW_USER_CREATION is a list.
ROOST_USER_CREATION_DENYLIST = cfg.get('user_denylist', [])

# Making this operator tweakable so we can experiment.
# JS roost had a 100 message limit. Snipe asked for 128 messages.
ROOST_MESSAGES_MAX_LIMIT = cfg.get('message_max_limit', 128)
