# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import bz2
import gzip
import json
import yaml
import os
import random
import shutil
import socket
import stat
import sys
import string
import xml.etree.ElementTree as ET
import zipfile

import filetype
import requests
import yaml
from wazuh_testing import logger



def read_json(file_path):
    """
    Read a JSON file from a given path, return a dictionary with the json data.

    Args:
        file_path (str): Path of the JSON file to be read.

    Returns:
        output(dict): Read json data.
    """
    with open(file_path, 'r') as f:
        output = json.loads(f.read())

    return output


def read_yaml(file_path):
    """Read a YAML file from a given path, return a dictionary with the YAML data

    Args:
        file_path (str): Path of the YAML file to be readed

    Returns:
       dict: Yaml structure.
    """
    with open(file_path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def get_list_of_content_yml(file_path, separator='_'):
    """Read a YAML file from a given path, return a list with the YAML data
    after apply filter

    Args:
        file_path (str): Path of the YAML file to be readed
        separator (str): filder to extract some part of yaml

    Returns:
       list: Yaml structure.
    """
    value_list = []
    with open(file_path) as f:
        value_list.append((yaml.safe_load(f), file_path.split(separator)[0]))

    return value_list


def truncate_file(file_path):
    """
    Truncate a file to reset its content.

    Args:
        file_path (str): Path of the file to be truncated.
    """
    with open(file_path, 'w'):
        pass


def random_unicode_char():
    """
    Generate a random unicode char from 0x0000 to 0xD7FF.

    Returns:
        str: Random unicode char.
    """
    return chr(random.randrange(0xD7FF))


def random_string_unicode(length, encode=None):
    """
    Generate a random unicode string with variable size and optionally encoded.

    Args:
        length (int) : String length.
        encode (str, optional) : Encoding type. Default `None`.

    Returns:
        (str or binary): Random unicode string.
    """
    st = str(''.join(format(random_unicode_char()) for i in range(length)))
    st = u"".join(st)

    if encode is not None:
        st = st.encode(encode)

    return st


def random_string(length, encode=None):
    """
    Generate a random alphanumeric string with variable size and optionally encoded.

    Args:
        length (int): String length.
        encode (str, optional): Encoding type. Default `None`.

    Returns:
        str or binary: Random string.
    """
    letters = string.ascii_letters + string.digits
    st = str(''.join(random.choice(letters) for i in range(length)))

    if encode is not None:
        st = st.encode(encode)

    return st

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

def read_file(file_path):
    with open(file_path) as f:
        data = f.read()
    return data


def write_file(file_path, data=''):
    with open(file_path, 'w') as f:
        f.write(data)


def write_file_without_close(file_path, data=''):
    """
    Create and write file without close

    Args:
        file_path: File path where the file will create.
        data: Data to write.

    """
    file = open(file_path, "w")
    file.write(data)


def read_json_file(file_path):
    return json.loads(read_file(file_path))


def write_json_file(file_path, data, ensure_ascii=False):
    """
    Write dict data to JSON file

    Args:
        file_path (str): File path where is located the JSON file to write.
        data (dict): Data to write.
        ensure_ascii (boolean) : If ensure_ascii is true, the output is guaranteed to have all incoming
                                 non-ASCII characters escaped. If ensure_ascii is false, these characters will
                                 be output as-is.
    """
    write_file(file_path, json.dumps(data, indent=4, ensure_ascii=ensure_ascii))


def write_yaml_file(file_path, data, allow_unicode=True, sort_keys=False):
    write_file(file_path, yaml.dump(data, allow_unicode=allow_unicode, sort_keys=sort_keys))


def rename_file(file_path, new_path):
    """
    Renames a file
    Args:
        file_path (str): File path of the file to rename.
        new_path (str): New file path after rename.
    """
    if os.path.exists(file_path):
        os.rename(file_path, new_path)


def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)


def delete_path_recursively(path):
    if os.path.exists(path):
        shutil.rmtree(path)


def download_file(source_url, dest_path):
    request = requests.get(source_url, allow_redirects=True)
    with open(dest_path, 'wb') as dest_file:
        dest_file.write(request.content)


def remove_file(file_path):
    """Remove a file or a directory path.

    Args:
        file_path (str): File or directory path to remove.
    """
    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            os.remove(file_path)
        elif os.path.isdir(file_path):
            delete_path_recursively(file_path)


def validate_json_file(file_path):
    try:
        with open(file_path) as file:
            json.loads(file.read())
        return True
    except json.decoder.JSONDecodeError:
        return False


def validate_yaml_file(file_path):
    try:
        read_yaml(file_path)
        return True
    except yaml.composer.ComposerError:
        return False


def validate_xml_file(file_path):
    try:
        ET.parse(file_path)
        return True
    except ET.ParseError:
        return False


def get_file_info(file_path, info_type="extension"):
    if os.path.exists(file_path) and filetype.guess(file_path) is not None:
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
    Function to read XML file as string.

    Args:
        file_path (str): File path where is the XML file.
        namespaces (list): List with data {name: namespace, url: url_namespace}.

    Returns:
        xml_string_data (str): XML string data
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
    Compresses a text file into a .gz one.

    Args:
        src_path : Path to source file.
        dest_path : Destination path of the output file.
    """
    with gzip.open(dest_path, 'wb') as dest:
        with open(src_path, 'rb') as source:
            dest.write(source.read())


def copy(source, destination):
    """
    Copy file with metadata and ownership to a specific destination.

    Args:
        source (str): Source file path to copy.
        destination (str): Destination file.
    """
    shutil.copy2(source, destination)
    source_stats = os.stat(source)

    if sys.platform != 'win32':
        os.chown(destination, source_stats[stat.ST_UID], source_stats[stat.ST_GID])


def bind_unix_socket(socket_path, protocol='TCP'):
    """Allow to create a unix socket if it does not exist.

    By default it is assigned owner and group wazuh and permissions 660.

    Args:
        socket_path (str): Path where create the unix socket.
        protocol (str): It can be TCP or UDP.
    """
    if not os.path.exists(socket_path) and sys.platform != 'win32':
        sock_type = socket.SOCK_STREAM if protocol.upper() == 'TCP' else socket.SOCK_DGRAM
        new_socket = socket.socket(socket.AF_UNIX, sock_type)
        new_socket.bind(socket_path)

        set_file_owner_and_group(socket_path, 'wazuh', 'wazuh')
        os.chmod(socket_path, 0o660)


def is_socket(socket_path):
    """Allow to check if a file path is a socket.

    Args:
        socket_path (str): File path to check.

    Returns:
        stat.S_ISSOCK (bool): True if is a socket, False otherwise.
    """
    mode = os.stat(socket_path).st_mode

    return stat.S_ISSOCK(mode)


def set_file_owner_and_group(file_path, owner, group):
    """Allow to change the owner and group of a directory or file.

    Args:
        file_path (str): Path to update owner and group.
        owner (str): Owner user name.
        group (str): Group name.

    Raises:
        KeyError: If owner or group does not exist.
    """
    if sys.platform != 'win32':
        from pwd import getpwnam
        from grp import getgrnam

        if os.path.exists(file_path):
            uid = getpwnam(owner).pw_uid
            gid = getgrnam(group).gr_gid

            os.chown(file_path, uid, gid)


def recursive_directory_creation(path):
    """Recursive function to create folders.

    Args:
        path (str): Path to create. If a folder doesn't exists, it will create it.
    """
    parent, _ = os.path.split(path)
    if parent != '' and not os.path.exists(parent):
        split = os.path.split(parent)
        recursive_directory_creation(split[0])
        os.mkdir(parent)

    if not os.path.exists(path):
        os.mkdir(path)


def move_everything_from_one_directory_to_another(source_directory, destination_directory):
    """Move all files and directories from one directory to another.

    Important note: Copied files must not exist on destination directory.

    Args:
        source_directory (str): Source_directory path.
        destination_directory (str): Destination_directory path.
    Raises:
        ValueError: If source_directory or destination_directory does not exist.
    """
    if not os.path.exists(source_directory):
        raise ValueError(f"{source_directory} does not exist")

    if not os.path.exists(destination_directory):
        raise ValueError(f"{destination_directory} does not exist")

    file_names = os.listdir(source_directory)

    for file_name in file_names:
        shutil.move(os.path.join(source_directory, file_name), destination_directory)


def join_path(path, system):
    """Create the path using the separator indicated for the operating system. Used for remote hosts configuration.

    Path can be defined by the following formats
       path = ['tmp', 'user', 'test']
       path = ['/tmp/user', test]

    Parameters:
        path (list(str)): Path list (one item for level).
        system (str): host system.

    Returns:
        str: Joined path.
    """
    result_path = []

    for item in path:
        if '\\' in item:
            result_path.extend([path_item for path_item in item.split('\\')])
        elif '/' in item:
            result_path.extend([path_item for path_item in item.split('/')])
        else:
            result_path.append(item)

    return '\\'.join(result_path) if system == 'windows' else '/'.join(result_path)


def count_file_lines(filepath):
    """Count number of lines of a specified file.

    Args:
        filepath (str): Absolute path of the file.

    Returns:
        Integer: Number of lines of the file.
    """
    with open(filepath, "r") as file:
        return sum(1 for line in file if line.strip())


def create_large_file(directory, file_path):
    """ Create a large file
    Args:
         directory(str): directory where the file will be genarated
         file_path(str): absolute path of the file
    """
    # If path exists delete it
    if os.path.exists(directory):
        delete_path_recursively(directory)
    # create directory
    os.mkdir(directory)
    file_size = 1024 * 1024 * 960  # 968 MB
    chunksize = 1024 * 768
    # create file and write to it.
    with open(file_path, "a") as f:
        while os.stat(file_path).st_size < file_size:
            f.write(random.choice(string.printable) * chunksize)


def download_text_file(file_url, local_destination_path):
    """Download a remote file with text/plain content type.

    Args:
        file_url (str): Remote URL path where the text file is located.
        local_destination_path (str): Local path where to save the file content.

    Raises:
        ValueError: if the URL content type is not 'text/plain'.

    """
    request = requests.get(file_url, allow_redirects=True)

    if 'text/plain' not in request.headers.get('content-type'):
        raise ValueError(f"The remote url {file_url} does not have text/plain content type to download it")

    open(local_destination_path, 'wb').write(request.content)


def get_file_lines(path):
    with open(path, "r+") as file_to_read:
        return file_to_read.readlines()
