# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

from wazuh_testing.fim import WAZUH_PATH
from wazuh_testing.tools.file import truncate_file


def generateString(stringLength=10, character='0'):
    """Generate a string with line breaks.

    Parameters
    ----------
    stringLength : int, optional
        Number of characters to add in the string. Default `10`
    character : str, optional
        Character to be added. Default `'0'`

    Returns
    -------
    random_str : str
        String with line breaks.
    """
    random_str = ''

    for i in range(stringLength):
        random_str += character

        if i % 127 == 0:
            random_str += '\n'

    return random_str


def translate_size(configured_size='1KB'):
    """
    Translate the configured size from string to number in bytes.

    Parameters
    ----------
    configured_size: str, optional
        Configured size to translate. Default `'1KB'`

    Returns
    -------
    translated_size: int
        Configured value in bytes.
    """
    translated_size = 0
    configured_value = int(configured_size[:-2])     # Store value ignoring the data unit
    data_unit = str(configured_size[-2:])

    if data_unit == 'KB':
        translated_size = configured_value * 1024
    elif data_unit == 'MB':
        translated_size = configured_value * 1024 * 1024
    elif data_unit == 'GB':
        translated_size = configured_value * 1024 * 1024 * 1024

    return translated_size


def disable_file_max_size():
    """
    Disable the syscheck.max_file_size option from the internal_options.conf file.
    """
    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.file_max_size=1024', 'syscheck.file_max_size=0')
            new_content += new_line

    truncate_file(internal_options)

    with open(internal_options, 'w') as f:
        f.write(new_content)


def restore_file_max_size():
    """
    Restore the syscheck.max_file_size option from the internal_options.conf file.
    """
    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.file_max_size=0', 'syscheck.file_max_size=1024')
            new_content += new_line

    truncate_file(internal_options)

    with open(internal_options, 'w') as f:
        f.write(new_content)
