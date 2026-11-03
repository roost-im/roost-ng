CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [{
                "address": "redis://127.0.0.1:6379/0",
                "socket_timeout": None,
            }],
        },
    },
}
