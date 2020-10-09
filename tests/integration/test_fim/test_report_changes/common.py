# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import re

from wazuh_testing.fim import WAZUH_PATH


def generate_string(stringLength=10, character='0'):
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
    generated_string = ''

    for i in range(stringLength):
        generated_string += character

        if i % 127 == 0:
            generated_string += '\n'

    return generated_string


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
    Disable the syscheck.file_max_size option from the internal_options.conf file.
    """
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
    else:
        internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.file_max_size=1024', 'syscheck.file_max_size=0')
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def restore_file_max_size():
    """
    Restore the syscheck.file_max_size option from the internal_options.conf file.
    """
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
    else:
        internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.file_max_size=0', 'syscheck.file_max_size=1024')
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def disable_rt_delay():
    """
    Disable the syscheck.rt_delay option from the internal_options.conf file.
    """
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
    else:
        internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.rt_delay=5', 'syscheck.rt_delay=1000')
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def restore_rt_delay():
    """
    Restore the syscheck.rt_delay option from the internal_options.conf file.
    """
    new_content = ''

    if sys.platform == 'win32':
        internal_options = os.path.join(WAZUH_PATH, 'internal_options.conf')
    else:
        internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line.replace('syscheck.rt_delay=1000', 'syscheck.rt_delay=5')
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def make_diff_file_path(folder='/testdir1', filename='regular_0'):
    """
    Generate diff file path.

    Parameters
    ----------
    folder : str, optional
        Containing folder. Default `/testdir1`
    filename : str, optional
        File name. Default `regular_0`

    Returns
    -------
    diff_file_path : str
        Path to compressed file.
    """
    diff_file_path = os.path.join(WAZUH_PATH, 'queue', 'diff', 'local')

    if sys.platform == 'win32':
        folder_components = re.match(r'^([a-zA-Z]):\\{1,2}(\w+)\\{0,2}$', folder)
        diff_file_path = os.path.join(diff_file_path, folder_components.group(1).lower(),
                                      folder_components.group(2).lower(), filename, 'last-entry.gz')
    else:
        diff_file_path = os.path.join(diff_file_path, folder.strip('/'), filename, 'last-entry.gz')

    return diff_file_path
