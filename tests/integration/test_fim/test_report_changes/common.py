# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


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
