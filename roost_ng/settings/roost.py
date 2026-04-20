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

def ROOST_CHECK_PUNT(znotice):
    """Hook to optionally drop certain messages before adding to DB

    Useful if there's a class with some useful messages, but also a high
    rate of messages that nobody needs to see that unnecessarily load the
    server.

    Returns a bool indicating whether or not to punt a message."""
    return False
