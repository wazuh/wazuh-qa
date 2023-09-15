# Copyright (C) 2015-2023, Wazuh Inc.
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
import re
import subprocess
import platform
import tempfile
import filetype
import requests
import yaml
import pytest
from stat import ST_ATIME, ST_MTIME
from wazuh_testing import logger, REGULAR, SYMLINK, HARDLINK

if sys.platform == 'win32':
    import win32con
    import win32api
    import win32security as win32sec
    import ntsecuritycon as ntc
    import pywintypes


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
    with open(file_path) as f:
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
    """Delete a regular file.

    Args:
        file_path (str): File path of the file to be deleted.
    """
    if os.path.exists(file_path):
        os.remove(file_path)


def delete_path_recursively(path):
    '''Remove a directory recursively.

    Args:
        path (str): Directory path.
    '''
    if os.path.exists(path):
        shutil.rmtree(path, onerror=on_write_error)


def on_write_error(function, path, exc_info):
    """ Error handler for functions that try to modify a file. If the error is due to an access error (read only file),
    it attempts to add write permission and then retries. If the error is for another reason it re-raises the error.

    Args:
        function (function): function that called the handler.
        path (str): Path to the file the function is trying to modify
        exc_info (object): function instance execution information. Passed in by function in runtime.

    Example:
        > shutil.rmtree(path, onerror=on_write_error)
    """
    import stat
    # Check if the error is an access error for Write permissions.
    if not os.access(path, os.W_OK):
        # Add write permissions so file can be edited and execute function.
        os.chmod(path, 0o0777)
        function(path)
    # If error is not Write access error, raise the error
    else:
        raise


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


def copy_files_in_folder(src_folder, dst_folder='/tmp', files_to_move=None):
    """Copy files from a folder to target folder
    Args:
        src_folder (str): directory path from where to copy files.
        dst_folder (str): directory path where files will be copied to.
        files_to_move (list): List with files to move copy from a folder.
    """
    file_list = []
    if os.path.isdir(src_folder):
        if files_to_move is None:
            for file in os.listdir(src_folder):
                file_list.append(file)
                copy(os.path.join(src_folder, file), dst_folder)
                remove_file(os.path.join(src_folder, file))
        else:
            for file in files_to_move:
                if os.path.isfile(os.path.join(src_folder, file)):
                    file_list.append(file)
                    copy(os.path.join(src_folder, file), dst_folder)
                    remove_file(os.path.join(src_folder, file))
    return file_list


def modify_all_files_in_folder(folder_path, data):
    """Write data into all files in a folder
    Args:
        file_path (str): File or directory path to modify.
        data (str): what to write into the file.
    """
    for file in os.listdir(folder_path):
        write_file(os.path.join(folder_path, file), data)


def delete_all_files_in_folder(folder_path):
    """ Remove al files inside a folder
    Args:
        file_path (str): File or directory path to remove.
    """
    for file in os.listdir(folder_path):
        os.remove(os.path.join(folder_path, file))


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
        os.mkdir(parent, mode=0o0777)

    if not os.path.exists(path):
        os.mkdir(path, mode=0o0777)


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


def replace_regex_in_file(search_regex, replace_regex, file_path):
    """Perform replacements in a file data according to the specified regex.

    Args:
        search_regex (list(str)): Search regex list.
        replace_regex (list(str)): Replacements regex list.
        file_path (str): File path to read and update.
    """
    if (len(search_regex) != len(replace_regex)):
        raise ValueError('search_regex has to have the same number of items than replace_regex. '
                         f"{len(search_regex)} != {len(replace_regex)}")

    # Read the file content
    file_data = read_file(file_path)

    # Perform the replacements
    for search, replace in zip(search_regex, replace_regex):
        file_data = re.sub(search, replace, file_data)

    # Write the file data
    write_file(file_path, file_data)


def _create_fifo(path, name):
    """Create a FIFO file.

    Args:
        path (str): path where the file will be created.
        name (str): file name.

    Raises:
        OSError: if `mkfifo` fails.
    """
    fifo_path = os.path.join(path, name)
    try:
        os.mkfifo(fifo_path)
    except OSError:
        raise


def _create_sym_link(path, name, target):
    """Create a symbolic link.

    Args:
        path (str): path where the symbolic link will be created.
        name (str): file name.
        target (str): path where the symbolic link will be pointing to.

    Raises:
        OSError: if `symlink` fails.
    """
    symlink_path = os.path.join(path, name)
    try:
        os.symlink(target, symlink_path)
    except OSError:
        raise


def _create_hard_link(path, name, target):
    """Create a hard link.

    Args:
        path (str): path where the hard link will be created.
        name (str): file name.
        target (str): path where the hard link will be pointing to.

    Raises:
        OSError: if `link` fails.
    """
    link_path = os.path.join(path, name)
    try:
        os.link(target, link_path)
    except OSError:
        raise


def _create_socket(path, name):
    """Create a Socket file.

    Args:
        path (str): path where the socket will be created.
        name (str): file name.

    Raises:
        OSError: if `unlink` fails.
    """
    socket_path = os.path.join(path, name)
    try:
        os.unlink(socket_path)
    except OSError:
        if os.path.exists(socket_path):
            raise
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(socket_path)


def _create_regular(path, name, content=''):
    """Create a regular file.

    Args:
        path (str): path where the regular file will be created.
        name (str): file name.
        content (str, optional): content of the created file. Default `''`
    """
    regular_path = os.path.join(path, name)
    mode = 'wb' if isinstance(content, bytes) else 'w'

    with open(regular_path, mode) as f:
        f.write(content)


def _create_regular_windows(path, name, content=''):
    """Create a regular file in Windows

    Args:
        path (str): path where the regular file will be created.
        name (str): file name.
        content (str, optional): content of the created file. Default `''`
    """
    regular_path = os.path.join(path, name)
    os.popen("echo " + content + " > " + regular_path + f" runas /user:{os.getlogin()}")


def create_file(type_, path, name, **kwargs):
    """Create a file in a given path. The path will be created in case it does not exists.

    Args:
        type_ (str): defined constant that specifies the type. It can be: FIFO, SYSLINK, Socket or REGULAR.
        path (str): path where the file will be created.
        name (str): file name.
        **kwargs: Arbitrary keyword arguments.

    Keyword Args:
            **content (str): content of the created regular file.
            **target (str): path where the link will be pointing to.

    Raises:
        ValueError: if `target` is missing for SYMLINK or HARDINK.
    """

    try:
        logger.info("Creating file " + str(os.path.join(path, name)) + " of " + str(type_) + " type")
        os.makedirs(path, exist_ok=True, mode=0o777)
        if type_ != REGULAR:
            try:
                kwargs.pop('content')
            except KeyError:
                pass
        if type_ in (SYMLINK, HARDLINK) and 'target' not in kwargs:
            raise ValueError(f"'target' param is mandatory for type {type_}")
        getattr(sys.modules[__name__], f'_create_{type_}')(path, name, **kwargs)
    except OSError:
        logger.info("File could not be created.")
        pytest.skip("OS does not allow creating this file.")


def modify_file_content(path, name, new_content=None, is_binary=False):
    """Modify the content of a file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
        new_content (str, optional): new content to append to the file. Previous content will remain. Defaults `None`
        is_binary (boolean, optional): True if the file's content is in binary format. False otherwise. Defaults `False`
    """
    path_to_file = os.path.join(path, name)
    logger.info("- Changing content of " + str(path_to_file))
    content = "1234567890qwertyu" if new_content is None else new_content
    with open(path_to_file, 'ab' if is_binary else 'a') as f:
        f.write(content.encode() if is_binary else content)


def modify_file_mtime(path, name):
    """Change the modification time of a file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    path_to_file = os.path.join(path, name)
    logger.info("- Changing mtime of " + str(path_to_file))
    stat = os.stat(path_to_file)
    access_time = stat[ST_ATIME]
    modification_time = stat[ST_MTIME]
    modification_time = modification_time + 1000
    os.utime(path_to_file, (access_time, modification_time))


def modify_file_owner(path, name):
    """Change the owner of a file. The new owner will be '1'.

    On Windows, uid will always be 0.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """

    def modify_file_owner_windows():
        cmd = f"takeown /S 127.0.0.1 /U {os.getlogin()} /F " + path_to_file
        subprocess.call(cmd)

    def modify_file_owner_unix():
        os.chown(path_to_file, 1, -1)

    path_to_file = os.path.join(path, name)
    logger.info("- Changing owner of " + str(path_to_file))

    if sys.platform == 'win32':
        modify_file_owner_windows()
    else:
        modify_file_owner_unix()


def modify_file_group(path, name):
    """Change the group of a file. The new group will be '1'.

    Available for UNIX. On Windows, gid will always be 0 and the group name will be blank.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform == 'win32':
        return

    path_to_file = os.path.join(path, name)
    logger.info("- Changing group of " + str(path_to_file))
    os.chown(path_to_file, -1, 1)


def modify_file_permission(path, name):
    """Change the permission of a file.

    On UNIX the new permissions will be '666'.
    On Windows, a list of denied and allowed permissions will be given for each user or group since version 3.8.0.
    Only works on NTFS partitions on Windows systems.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """

    def modify_file_permission_windows():
        user, _, _ = win32sec.LookupAccountName(None, f"{platform.node()}\\{os.getlogin()}")
        sd = win32sec.GetFileSecurity(path_to_file, win32sec.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32sec.ACL_REVISION, ntc.FILE_ALL_ACCESS, user)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32sec.SetFileSecurity(path_to_file, win32sec.DACL_SECURITY_INFORMATION, sd)

    def modify_file_permission_unix():
        os.chmod(path_to_file, 0o666)

    path_to_file = os.path.join(path, name)

    logger.info("- Changing permission of " + str(path_to_file))

    if sys.platform == 'win32':
        modify_file_permission_windows()
    else:
        modify_file_permission_unix()


def modify_file_inode(path, name):
    """Change the inode of a file for Linux.

    On Windows, this function does nothing.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform == 'win32':
        return

    logger.info("- Changing inode of " + str(os.path.join(path, name)))
    inode_file = 'inodetmp'
    path_to_file = os.path.join(path, name)

    shutil.copy2(path_to_file, os.path.join(tempfile.gettempdir(), inode_file))
    shutil.move(os.path.join(tempfile.gettempdir(), inode_file), path_to_file)


def modify_file_win_attributes(path, name):
    """Change the attribute of a file in Windows

    On other OS, this function does nothing.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
    """
    if sys.platform != 'win32':
        return

    logger.info("- Changing win attributes of " + str(os.path.join(path, name)))
    path_to_file = os.path.join(path, name)
    win32api.SetFileAttributes(path_to_file, win32con.FILE_ATTRIBUTE_HIDDEN)


def modify_file(path, name, new_content=None, is_binary=False):
    """Modify a Regular file.

    Args:
        path (str): path to the file to be modified.
        name (str): name of the file to be modified.
        new_content (str, optional): new content to add to the file. Defaults `None`.
        is_binary: (boolean, optional): True if the file is binary. False otherwise. Defaults `False`
    """
    logger.info("Modifying file " + str(os.path.join(path, name)))
    modify_file_inode(path, name)
    modify_file_content(path, name, new_content, is_binary)
    modify_file_mtime(path, name)
    modify_file_owner(path, name)
    modify_file_group(path, name)
    modify_file_permission(path, name)
    modify_file_win_attributes(path, name)
