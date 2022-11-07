# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from wazuh_testing import logger
from wazuh_testing.modules import fim


if sys.platform == 'win32':
    import win32con
    import win32api
    import pywintypes

def create_registry(key, subkey, arch):
    """Create a registry given the key and the subkey. The registry is opened if it already exists.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).

    Returns:
         str: the key handle of the new/opened key.
    """

    if sys.platform == 'win32':
        try:
            logger.info("Creating registry key " + str(os.path.join(fim.registry_class_name[key], subkey)))

            key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)

            return key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            logger.warning(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            logger.warning(f"Registry could not be created: {e}")


def delete_registry(key, subkey, arch):
    """Delete a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    if sys.platform == 'win32':
        print_arch = '[x64]' if arch == KEY_WOW64_64KEY else '[x32]'
        logger.info(f"Removing registry key {print_arch}{str(os.path.join(fim.registry_class_name[key], subkey))}")

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            win32api.RegDeleteTree(key_h, None)
            win32api.RegDeleteKeyEx(key, subkey, samDesired=arch)
        except OSError as e:
            logger.warning(f"Couldn't remove registry key {str(os.path.join(fim.registry_class_name[key], subkey))}: {e}")
        except pywintypes.error as e:
            logger.warning(f"Couldn't remove registry key {str(os.path.join(fim.registry_class_name[key], subkey))}: {e}")