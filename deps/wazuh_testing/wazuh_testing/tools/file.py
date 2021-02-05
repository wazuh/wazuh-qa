# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import bz2
import gzip
import json
import os
import random
import string
import xml.etree.ElementTree as ET
import zipfile
from os.path import exists

import filetype
import requests


def read_json(file_path):
    """
    Read a JSON file from a given path, return a dictionary with the json data

    Parameters
    ----------
    file_path : str
        Path of the JSON file to be readed
    """
    # Read JSON data templates
    with open(file_path, 'r') as f:
        output = json.loads(f.read())

    return output


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


def download_file(source_url, dest_path):
    request = requests.get(source_url, allow_redirects=True)
    with open(dest_path, 'wb') as dest_file:
        dest_file.write(request.content)


def remove_file(file_path):
    if exists(file_path):
        os.remove(file_path)


def validate_json_file(file_path):
    try:
        with open(file_path) as file:
            json.loads(file.read())
        return True
    except json.decoder.JSONDecodeError:
        return False


def validate_xml_file(file_path):
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        return False


def get_file_info(file_path, info_type="extension"):
    if exists(file_path) and filetype.guess(file_path) is not None:
        file = filetype.guess(file_path)
        return file.extension if info_type == "extension" else file.mime


def decompress_gzip(gzip_file_path, dest_file_path):
    with gzip.open(gzip_file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
        dest.write(source.read())


def decompress_bz2(bz2_file_path, dest_file_path):
    with open(bz2_file_path, 'rb') as source, open(dest_file_path, 'wb') as dest:
        dest.write(bz2.decompress(source.read()))


def decompress_zip(zip_file_path, dest_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_reference:
        zip_reference.extractall(dest_file_path)


def read_xml_file(file_path, namespaces=None, xml_header=False):
    """
    Function to read XML file as string

    Parameters
    ----------
    file_path: str
        File path where is the XML file
    namespaces: list
        List with data {name: namespace, url: url_namespace}

    Returns
    -------
    str:
        XML string data
    """
    xml_root = ET.parse(file_path).getroot()

    if namespaces is not None:
        for namespace in namespaces:
            try:
                ET.register_namespace(namespace['name'], namespace['url'])
            except KeyError:
                pass

    if xml_header:
        xml_string_data = ET.tostring(xml_root, encoding='utf8', method='xml').decode()
    else:
        xml_string_data = ET.tostring(xml_root).decode()

    return xml_string_data


def compress_gzip_file(src_path, dest_path):
    """
    Compresses a text file into a .gz one

    Parameters
    ----------
    src_path : path
        Path to source file.
    dest_path : path
        Destination path of the output file.
    """
    with gzip.open(dest_path, 'wb') as dest:
        with open(src_path, 'rb') as source:
            dest.write(source.read())
