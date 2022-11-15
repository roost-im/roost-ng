# This file is imported for side-effects in the pylintrc init hook.
# This lets us add more to the init hook without having it grow
# unbounded.

import os

# Assume the usual django config if unspecified.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roost_ng.settings')
