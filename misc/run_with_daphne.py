#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys

from daphne.cli import CommandLineInterface


def main():
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'roost_ng.settings')

    import roost_backend.subscribers

    with roost_backend.subscribers.Manager():
        sys.exit(CommandLineInterface.entrypoint())


if __name__ == '__main__':
    # This lives in misc; fix sys.path so it's like we're running at the project root.
    sys.path = [os.path.join(sys.path[0], '..')] + sys.path[1:]
    main()
