# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import random
import string


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