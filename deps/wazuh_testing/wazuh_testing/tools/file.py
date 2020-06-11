# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import random
import string
import json
import os
import xml.etree.ElementTree as ET
import filetype
import requests
import gzip
import bz2


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
    with open(file_path) as f:
        data = f.read()
    return data


def write_file(file_path, data):
    with open(file_path, 'w') as f:
        f.write(data)


def read_json_file(file_path):
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


def check_file_exist(file_path):
    return os.path.exists(file_path)


def download_file(source_url, dest_path):
    r = requests.get(source_url, allow_redirects=True)
    with open(dest_path, 'wb') as f:
        f.write(r.content)


def remove_file(file_path):
    if check_file_exist(file_path):
        os.remove(file_path)


def validate_json_file(file_path):
    try:
        with open(file_path) as f:
            json.loads(f.read())
        return True
    except json.decoder.JSONDecodeError:
        return False


def validate_xml_file(file_path):
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        return False


def get_file_extension(file_path):
    if check_file_exist(file_path) and filetype.guess(file_path) is not None:
        return filetype.guess(file_path).extension


def get_file_mime_type(file_path):
    if check_file_exist(file_path) and filetype.guess(file_path) is not None:
        return filetype.guess(file_path).mime


def decompress_gzip(gzip_file_path, dest_file_path):
    with gzip.open(gzip_file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
        dest.write(source.read())


def decompress_bz2(bz2_file_path, dest_file_path):
    with open(bz2_file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
        dest.write(bz2.decompress(source.read()))
