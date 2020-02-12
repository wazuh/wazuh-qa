#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import pwd
import random

def random_mode():
    """ 
    Returns a random file permission
    
    File permission in unix use octal format, but os.chmod expects a decimal.
    Numbers 0 and 511 are the min and max (decimal) numbers which chmod accepts,
    being 0 equivalent to 000 and 511 equivalent to 777 in octal.
    """
    return random.randint(0, 511)


def modify_file(filepath, owner):
    """
        Modify a file owner, group and permissions.
        
        :param str filepath: Full path of the file
        :param str owner: File owner
        :return: Returns a dictionary with the change metadata
    """
    pwinfo = pwd.getpwnam(owner)
    uid = pwinfo.pw_uid
    gid = pwinfo.pw_gid
    mode = random_mode()
    os.chmod(filepath, mode)

def main():
    pass

if __name__ == "__main__":
    main()
