#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import random


if sys.version_info.major < 3:
    print('ERROR: Python 2 is not supported.')
    sys.exit(1)


def random_mode():
    """
    Returns a random file permission

    File permission in unix use octal format, but os.chmod expects a decimal.
    Numbers 0 and 511 are the min and max (decimal) numbers accepted,
    being 0 equivalent to 000 and 511 equivalent to 777 in octal.
    """
    return random.randint(0, 511)


def modify_file_content(filepath):
    """
        Modify file content by adding a random number of bytes
    """
    content = 'qazxswedcvbnmklpoiuytggdfert'*random.randint(1, 10)
    content += str(random.random())
    with open(filepath, 'ab') as f:
        f.write(bytes(content, 'utf8'))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('filelist', action="store")
    args = parser.parse_args()
    filelist = args.filelist
    with open(filelist) as flist:
        for path in flist:
            modify_file_content(path[:-1])


if __name__ == "__main__":
    main()
