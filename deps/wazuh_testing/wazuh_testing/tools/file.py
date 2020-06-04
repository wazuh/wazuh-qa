# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import random
import string
import json


def truncate_file(file_path):
    """
    Truncate a file to reset its content.

    Parameters
    ----------
    file_path : str
        Path of the file to be truncated.
    """
    with open(file_path, 'w'):
        pass


def random_unicode_char():
    """
    Generate a random unicode char from 0x0000 to 0xD7FF.

    Returns
    -------
    str
        Random unicode char.
    """
    return chr(random.randrange(0xD7FF))


def random_string_unicode(length, encode=None):
    """
    Generate a random unicode string with variable size and optionally encoded.

    Parameters
    ----------
    length : int
        String length.
    encode : str, optional
        Encoding type. Default `None`

    Returns
    -------
    str or binary
        Random unicode string.
    """
    st = str(''.join(format(random_unicode_char()) for i in range(length)))
    st = u"".join(st)

    if encode is not None:
        st = st.encode(encode)

    return st


def random_string(length, encode=None):
    """
    Generate a random alphanumeric string with variable size and optionally encoded.

    Parameters
    ----------
    length : int
        String length.
    encode : str, optional
        Encoding type. Default `None`

    Returns
    -------
    str or binary
        Random string.
    """
    letters = string.ascii_letters + string.digits
    st = str(''.join(random.choice(letters) for i in range(length)))

    if encode is not None:
        st = st.encode(encode)

    return st


def read_file(file_path):
    """
    Read file data

    Parameters
    ----------
    file_path : str
        File path where is located the file to read

    Returns
    -------
    str
        File string data
    """
    with open(file_path) as f:
        data = f.read()
    return data


def write_file(file_path, data):
    """
    Write data to file

    Parameters
    ----------
    file_path : str
        File path where is located the file to write
    data : str
        Data to write
    """
    with open(file_path, 'w') as f:
        f.write(data)


def read_json_file(file_path):
    """
    Read JSON file data

    Parameters
    ----------
    file_path : str
        File path where is located the JSON file to read

    Returns
    -------
    dict
        File JSON data
    """
    return json.loads(read_file(file_path))


def write_json_file(file_path, data, ensure_ascii=False):
    """
    Write dict data to JSON file

    Parameters
    ----------
    file_path : str
        File path where is located the JSON file to write
    data : dict
        Data to write
    ensure_ascii : boolean
        If ensure_ascii is true, the output is guaranteed to have all incoming non-ASCII characters
        escaped. If ensure_ascii is false, these characters will be output as-is.
    """
    write_file(file_path, json.dumps(data, indent=4, ensure_ascii=ensure_ascii))
