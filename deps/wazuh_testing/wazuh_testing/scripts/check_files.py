import argparse
import os
import stat
import grp
import pwd
import json
import logging
import hashlib
from datetime import datetime

script_logger = logging.getLogger('check_files')
_filemode_list = [
    {
        stat.S_IFLNK: "l",
        stat.S_IFREG: "-",
        stat.S_IFBLK: "b",
        stat.S_IFDIR: "d",
        stat.S_IFCHR: "c",
        stat.S_IFIFO: "p"
    },
    {
        stat.S_IRUSR: "r"
    },
    {
        stat.S_IWUSR: "w"
    },
    {
        stat.S_IXUSR | stat.S_ISUID: "s",
        stat.S_ISUID: "S",
        stat.S_IXUSR: "x"
    },
    {
        stat.S_IRGRP: "r"
    },
    {
        stat.S_IWGRP: "w"
    },
    {
        stat.S_IXGRP | stat.S_ISGID: "s",
        stat.S_ISGID: "S",
        stat.S_IXGRP: "x"
    },
    {
        stat.S_IROTH: "r"
    },
    {
        stat.S_IWOTH: "w"
    },
    {
        stat.S_IXOTH | stat.S_ISVTX: "t",
        stat.S_ISVTX: "T",
        stat.S_IXOTH: "x"
    }
]


def set_parameters(parameters):
    """Configure the script logger

    Args:
        parameters (ArgumentParser): script parameters.
    """
    logging_level = logging.DEBUG if parameters.debug else logging.INFO
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    script_logger.setLevel(logging_level)
    script_logger.addHandler(handler)


def get_human_readable_bytes(bytes):
    """Get a human readable string from a count of bytes.

    Args:
        bytes (int): Count of bytes.

    Returns:
        (string): Human readable count of bytes/kilobytes/megabytes/gigabytes.
    """
    gb = 1024*1024*1024
    mb = 1024*1024
    kb = 1024

    if bytes > gb:
        return f"{format(bytes/gb, '.2f')}GB"
    elif bytes > mb:
        return f"{format(bytes/mb, '.2f')}MB"
    elif bytes > kb:
        return f"{format(bytes/kb, '.2f')}KB"
    else:
        return f"{bytes}B"


def get_check_files_data(path='/', ignored_paths=[]):
    """Get a dictionary with all check-files information recursively from a specific path

    Args:
        path (string): Root path from which to obtain the information
        ignored_paths (list): Path list to be ignored

    Returns:
        dict: Dictonary with all check files corresponding to the analized path. It has the following format:
            "/var/ossec/active-response":{
                    "group": "wazuh",
                    "mode": "0750",
                    "prot": "drwxr-x---",
                    "type": "directory",
                    "user": "root"
            }, ...
    """
    files_items_dict = {}

    script_logger.info(f"Ignoring the following paths: {ignored_paths}")
    script_logger.info(f"Getting check-files data from {path}")

    # If the given path is not a dir
    if os.path.exists(path) and not os.path.isdir(path):
        try:
            files_items_dict[path] = get_data_information(path)
        except OSError:  # Ignore errors like "No such device or address" due to dynamic and temporary files
            pass

    # If the given path is a dir, walk through the dir tree
    for (dirpath, _, filenames) in os.walk(path, followlinks=False):
        skip_path_checking = False

        for ignore_path in ignored_paths:
            if ignore_path == dirpath[0:len(ignore_path)]:
                skip_path_checking = True

        if not skip_path_checking:
            # Get the dir data
            if os.path.exists(dirpath):
                try:
                    files_items_dict[dirpath] = get_data_information(dirpath)
                except OSError:  # Ignore errors like "No such device or address" due to dynamic and temporary files
                    pass

            # Get the dir content data
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)

                if file_path not in ignored_paths and os.path.exists(file_path):
                    try:
                        files_items_dict[file_path] = get_data_information(file_path)
                    except OSError:  # Ignore errors like "No such device or address" due to dynamic and temporary files
                        pass

    return files_items_dict


def get_filemode(mode):
    """Convert a file's mode to a string in format '-rwxrwxrwx'.

    Args:
       mode (int): st_mode field of a file or directory from os.stat_result (Example: 16893)

    Returns:
        string: Permissions set '-rwxrwxrwx'

    Example:
        33204 --> -rw-rw-r--
    """
    file_permission = []

    for item in _filemode_list:
        for stat_flag, stat_value in item.items():
            if mode & stat_flag == stat_flag:
                file_permission.append(stat_value)
                break
        else:
            file_permission.append('-')

    return ''.join(file_permission)


def get_data_information(item):
    """Get the check-file data from a file or directory.

    Args:
        item (string): File path or directory.

    Returns:
        dict: Dictionary with checkfile data.
    """
    stat_info = os.stat(item)
    try:
        user = pwd.getpwuid(stat_info.st_uid)[0]
    except KeyError:
        user = 'user has no entry in etc/passwd.'
    try:
        group = grp.getgrgid(stat_info.st_gid)[0]
    except KeyError:
        group = 'group has no entry in /etc/group.'
    mode = oct(stat.S_IMODE(stat_info.st_mode))
    mode_str = str(mode).replace('o', '')
    mode = mode_str[-3:] if len(mode_str) > 3 else mode_str
    _type = 'directory' if os.path.isdir(item) else 'file'
    permissions = get_filemode(stat_info.st_mode)
    last_update = datetime.fromtimestamp(os.path.getmtime(item)).strftime('%Y-%m-%d %H:%M:%S')
    size = get_human_readable_bytes(stat_info.st_size)
    if _type != 'directory':
        checksum = hashlib.md5(open(item, 'rb').read()).hexdigest()

        return {'type': _type, 'user': user, 'group': group, 'mode': mode, 'permissions': permissions,
                'last_update': last_update, 'md5sum': checksum, 'size': size}
    else:
        return {'type': _type, 'user': user, 'group': group, 'mode': mode, 'permissions': permissions,
                'last_update': last_update, 'size': size}


def write_data_to_file(data, output_file_path):
    """Save the check-files data in the specified file path

    Args:
        data (dict): Check-files data
        output_file_path (string): file path to save the data
    """
    output_dir = os.path.split(output_file_path)[0]

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    with open(output_file_path, 'w') as file:
        file.write(json.dumps(data, indent=4))

    script_logger.info(f"The check-files data has been written in {output_file_path} file")


def get_script_parameters():
    """Process the script parameters

    Returns:
        ArgumentParser: Parameters and their values
    """
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-p", "--path", type=str, required=False, default='/',
                            help="Path base to inspect files recursively")
    arg_parser.add_argument("-i", "--ignore", type=str, nargs='+', help='List of paths to ignore')
    arg_parser.add_argument("-o", "--output-file", type=str, help='path to store the results')
    arg_parser.add_argument('-d', '--debug', action='store_true', help='Run in debug mode.')

    return arg_parser.parse_args()


def main():
    arguments = get_script_parameters()
    set_parameters(arguments)

    ignored_paths = arguments.ignore if arguments.ignore else []

    # Get the check-files info
    check_files_data = get_check_files_data(arguments.path, ignored_paths)

    # Save the check-files data to a file if specified, otherwise will be logged in the stdout
    if arguments.output_file:
        write_data_to_file(check_files_data, arguments.output_file)
    else:
        script_logger.info(json.dumps(check_files_data, indent=4))


if __name__ == '__main__':
    main()
