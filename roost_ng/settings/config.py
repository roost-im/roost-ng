import os

import yaml

configfile = os.getenv('ROOST_NG_CONFIGFILE', '/etc/roost-ng/config.yml')

config = {}

try:
    with open(configfile, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    pass
