import os

import yaml

configfile = os.getenv('ROOST_NG_CONFIGFILE', '/etc/roost-ng/config.yml')

config = {}

try:
    with open(configfile, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    pass

def get_config_for_module(mod):
    if isinstance(mod, str):
        mod = mod.rsplit('.', 1)[-1]
    return config.get(mod, {})
