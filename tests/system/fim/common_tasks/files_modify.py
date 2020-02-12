#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import sys
import pwd
import grp
import random

if sys.version_info.major < 3:
    print('ERROR: Python 2 is not supported.')
    sys.exit(1)

# predefined users and groups on the host
USERS = 'devops1 devops2 devops3 ops1 ops2'.split()
GROUPS = 'devops operations'.split()

try:
    for user in USERS:
        pwd.getpwnam(user)
    for group in GROUPS:
        grp.getgrnam(group)
except:
    print('ERROR: The users {} and groups {} must exist on the system.'
                    .format(USERS, GROUPS))
    sys.exit(1)


def random_mode():
    """ 
    Returns a random file permission
    
    File permission in unix use octal format, but os.chmod expects a decimal.
    Numbers 0 and 511 are the min and max (decimal) numbers which chmod accepts,
    being 0 equivalent to 000 and 511 equivalent to 777 in octal.
    """
    return random.randint(0, 511)


def modify_file(filepath, owner, group, mode):
    """
        Modify a file owner, group and permissions.
        
        :param str filepath: Full path of the file
        :param str owner: File owner
        :param str group: File group
        :param int mode: File permissions in decimal format
        :return: Returns a dictionary with the change metadata
    """
    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(filepath, uid, gid)
    os.chmod(filepath, mode)
    return {
        'path': filepath,
        'uid': uid,
        'gid': gid,
        'mode': oct(mode).split('o')[1].zfill(3) # convert to octal string
        }


def main():
    changed_files = []
    for i in range(1,100):
        path = '/opt/{}'.format(i)
        mode = random_mode()
        user = random.choice(USERS)
        group = random.choice(GROUPS)
        change = modify_file(path, user, group, mode)
        changed_files.append(change)
    from pprint import pprint
    pprint(changed_files)


if __name__ == "__main__":
    main()
