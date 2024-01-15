#!/usr/bin/env python3

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is used to check that all installation files (except ignored and exceptions) have the expected permissions, owner, group ...
# It is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import argparse
import os
import grp
from pathlib import Path
import pwd
import stat
import glob
import sys
from distutils.version import LooseVersion

from .utils import read_json_file

OSSEC_PATH = '/var/ossec'
ALL_FILES_DATA = Path(__file__).parent / 'data' / 'check_files_data.json'
FILES_TO_CHECK = Path(__file__).parent / 'data' / 'check_files_templates.json'


# ---------------------------------------------------------------------------------------------------------------

# Aux functions

# ---------------------------------------------------------------------------------------------------------------

"""
    Convert a file's mode to a string of the form '-rwxrwxrwx'.

    Parameters:
        - mode: st_mode field of a file or directory from os.stat_result (Example: 16893)
    Return:
        String of the permissions set '-rwxrwxrwx'

    Example:
        33204 --> -rw-rw-r--

"""


def mode_to_str(mode: int) -> str:
    # # Define permission characters
    # permissions = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']

    # # Extract permission bits
    # user = permissions[(mode >> 6) & 0b111]
    # group = permissions[(mode >> 3) & 0b111]
    # others = permissions[mode & 0b111]

    # # Check for directory and sticky bit
    # file_type = 'd' if mode & stat.S_IFDIR == stat.S_IFDIR else '-'
    # sticky_bit = 'T' if mode & 0o1000 and others[2] == '-' else others[2]

    # # Combine permission bits
    # return f'{file_type}{user}{group}{others[:2]}{sticky_bit}'

# def mode_to_str(mode):
    _filemode_table = (
        ((stat.S_IFLNK, "l"),
        (stat.S_IFREG, "-"),
        (stat.S_IFBLK, "b"),
        (stat.S_IFDIR, "d"),
        (stat.S_IFCHR, "c"),
        (stat.S_IFIFO, "p")),

        ((stat.S_IRUSR, "r"),),
        ((stat.S_IWUSR, "w"),),
        ((stat.S_IXUSR | stat.S_ISUID, "s"),
        (stat.S_ISUID, "S"),
        (stat.S_IXUSR, "x")),

        ((stat.S_IRGRP, "r"),),
        ((stat.S_IWGRP, "w"),),
        ((stat.S_IXGRP | stat.S_ISGID, "s"),
        (stat.S_ISGID, "S"),
        (stat.S_IXGRP, "x")),

        ((stat.S_IROTH, "r"),),
        ((stat.S_IWOTH, "w"),),
        ((stat.S_IXOTH | stat.S_ISVTX, "t"),
        (stat.S_ISVTX, "T"),
        (stat.S_IXOTH, "x"))
    )
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)

# ---------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------

"""
    Get the checkfile data from a file or directory.

    Parameters:
        - item: filepath or directory.

    Return:
        Dictonary with checkfile data.

    Example:
        '/var/ossec/active-response' -->
            {
                "group": "wazuh",
                "mode": "0750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
            }
"""


def get_data(path: str | Path) -> dict:
    # Get stat information of the file or directory
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f'File or directory {path} does not exist')

    # Hardcoded for /var/ossec/api/configuration/auth/htpasswd
    if str(path) == f'{OSSEC_PATH}/api/configuration/auth/htpasswd':
        return {u'group': u'root',
                u'target': u'/var/ossec/api/node_modules/htpasswd/bin/htpasswd',
                u'mode': u'0777',
                u'prot': u'lrwxrwxrwx',
                u'type': u'link',
                u'user': u'root'}

    stat_info = os.stat(path)

    user = pwd.getpwuid(stat_info.st_uid)[0]
    group = grp.getgrgid(stat_info.st_gid)[0]
    mode = str(oct(stat.S_IMODE(stat_info.st_mode))).replace('o', '')
    prot = mode_to_str(stat_info.st_mode)
    type = "directory" if path.is_dir() else "file"

    if len(mode) > 4:
        mode = mode[-4:]

    return {'group': group, 'mode': mode, 'prot': prot, 'type': type, 'user': user}
# {'group': 'ossec', 'mode': '0770', 'prot': 'drwxrwx---', 'type': 'directory', 'user': 'root'}

# def get_data(path: str | Path):
#     # Get stat information of the file or directory
#     if not Path(path).exists():
#         raise FileNotFoundError(f'File or directory {path} does not exist')
#     stat_info = os.stat(path)

#     # Extract user, group, and other permission bits
#     user_perm = stat_info.st_mode >> 6 & 0o7
#     group_perm = stat_info.st_mode >> 3 & 0o7
#     others_perm = stat_info.st_mode & 0o7

#     # Get the file type
#     file_type = "file"
#     if stat.S_ISDIR(stat_info.st_mode):
#         file_type = "directory"
#     elif stat.S_ISLNK(stat_info.st_mode):
#         file_type = "symlink"

#     # Create the dictionary with checkfile data
#     checkfile_data = {
#         "user": os.getpwuid(stat_info.st_uid).pw_name,
#         "group": os.getgrgid(stat_info.st_gid).gr_name,
#         "mode": f'{user_perm}{group_perm}{others_perm}',
#         "prot": mode_to_str(stat_info.st_mode),
#         "type": file_type
#     }

#     return checkfile_data
# def get_checkfile_data(item):
#     # Get stat info
#     stat_info = os.stat(item)

#     # Get user and group
#     user = pwd.getpwuid(stat_info.st_uid)[0]
#     group = grp.getgrgid(stat_info.st_gid)[0]

#     # Get mode
#     mode = oct(stat.S_IMODE(stat_info.st_mode))

#     # Get type
#     type = 'directory' if stat.S_ISDIR(stat_info.st_mode) else 'file'

#     # Get permissions string
#     prot = mode_to_str(stat_info.st_mode)  # Assuming you have the convert_mode_to_string function defined

#     # Return checkfile data
#     return {'group': group, 'mode': mode, 'prot': prot, 'type': type, 'user': user}
# ---------------------------------------------------------------------------------------------------------------

"""
    Checks if a version belongs to a range of versions.

    Parameters:
        - check_version: filepath or directory.
        - lower_version: Lower range limit.
        - higher_version: Upper range limit.

    Return:
        True if the version to be checked belongs to the range, False otherwise

    Example:
        3.9.5, [3.9.0, 3.10.0] --> True
        3.9.5  [3.9.0, 3.9.4] --> False
"""


def in_version(check_version: str, lower_version: str, higher_version: str) -> bool:
    if not LooseVersion(check_version) >= LooseVersion(lower_version):
        return False
    if not LooseVersion(check_version) <= LooseVersion(higher_version):
        return False
    return True

# ---------------------------------------------------------------------------------------------------------------


"""
    Get the data for a specific version in any template file for check files

    Parameters:
        - version: Version to obtain the data
        - json_data: json data with check files template

    Return:
        Data structure (list or dictionary) that stores checkfile data for a particular version
    Example:
       3.9.0 --> [1,3,4,5,6,8,9, ...]
"""


def get_version_template_data(version: str, json_data: dict) -> list | dict:
    if not version in json_data['unmatch']:
        return json_data['last_data']['data']

    position = None
    for idx, item in enumerate(json_data['other']['groups']):
        if in_version(version, item[0], item[1]):
            position = idx
    if position == None:
        raise Exception(f"No group found for the version {version}")

    return json_data['other']['groupData'][position]['data']

# ---------------------------------------------------------------------------------------------------------------


"""
    Read the check files database and get all the identifiers of a particular version to return an information
    map with all the check files of that version.

    Parameters:
        - check_files_template_path: Path where the is check files template (For that type of operating system and test)
        - version: version to check
        - target: [manager, agent]

    Return:
        Dictonary with all check files corresponding to that version. It has the following format:

        "/var/ossec/active-response":{
            "class": "static",
                "group": "wazuh",
                "mode": "0750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
        }, ...
"""


def read_template_items(component: str, version: str = 'last'):
    all_files = read_json_file(ALL_FILES_DATA)['data']
    to_check = read_json_file(FILES_TO_CHECK)[component][version]
    items = {i['name']: i['description'] for i in all_files if i['id'] in to_check}

    return items

# ---------------------------------------------------------------------------------------------------------------


"""
    Read exception data according to version. Common exceptions ossec.log, ossec.json api.log client.keys
    > Note: All exception files are named the same way, so when you call this script, you need to have only
            copied the file with the correct exceptions.

    Parameters:
        - version: version to obtain the data
        - target: [manager, agent]

    Return:
        Exception List for a Version.

    Example:
        3.9.5 --> ['/var/ossec/example', '/var/ossec/example2' ...]
"""


def read_exception_data(version: str, target: str, json_path: str | Path = 'check_files_exceptions.json') -> list:
    json = read_json_file(json_path)
    data = get_version_template_data(version, json[target])

    return data

# ---------------------------------------------------------------------------------------------------------------

# Main functions

# ---------------------------------------------------------------------------------------------------------------


"""
    Get a dictionary with all checkfile information from all files and directories located in a specific path

    Parameters:
        - ossec_path: Path where the installation is located.

    Return:
        Dictonary with all check files corresponding to the installed files. It has the following format:

        "/var/ossec/active-response":{
            "class": "static",
                "group": "wazuh",
                "mode": "0750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
        }, ...
"""


def get_current_items(ossec_path='/var/ossec', ignore_names=[]):

    ignore_names = set(ignore_names)
    current_items = {}

    for dirpath, _, filenames in os.walk(ossec_path, followlinks=False):
        if not dirpath in ignore_names:
            current_items[dirpath] = get_data(dirpath)

            for filename in (f for f in filenames if not f.endswith('.pyc')):
                file_path = str(Path(dirpath, filename))
                if not file_path in ignore_names:
                    current_items[file_path] = get_data(file_path)

    return current_items
    ignore_names = set(ignore_names)
    c_items = {}

    for dirpath, _, filenames in os.walk(ossec_path, followlinks=False):
        if dirpath not in ignore_names:
            c_items[dirpath] = get_data(dirpath)

            for filename in (f for f in filenames if not f.endswith('.pyc')):
                file_path = os.path.join(dirpath, filename)
                if file_path not in ignore_names:
                    c_items[file_path] = get_data(file_path)

    return c_items  
# ---------------------------------------------------------------------------------------------------------------


"""
    Obtains all check files of a version and separates them into two dictionaries, depending on whether they are
    static or dynamic class.

    Parameters:
        - template_path: Path where the is check files template (For that type of operating system and test)
        - version: Version to check
        - target: [manager, agent]
        - exceptions: Files that are not in the check files database and want to be ignored

    Return:
       template_static and template_dynamic dictionaries with all check files corresponding to the installed files. It has the following format:

        template_static:{
            "/var/ossec/active-response":{
                "class": "static",
                    "group": "wazuh",
                    "mode": "0750",
                    "prot": "drwxr-x---",
                    "type": "directory",
                    "user": "root"
            }, ...
        }

        template_dynamic:{
            "/var/ossec/etc/ossec.bck":{
                "group": "wazuh",
                "mode": "0660",
                "prot": "-rw-rw----",
                "type": "file",
                "user": "root"
            }, ...
        }
"""


def get_template_items(component: str, exceptions: list = None, wazuh_path: str | Path = None) -> tuple[dict, dict]:

    template_static = {}
    template_dynamic = {}

    data = read_template_items(component)

    if exceptions:
        [data.pop(item, None) for item in exceptions]

    if wazuh_path:
        data = {k.replace('/var/ossec', str(wazuh_path)): v for k, v in data.items()}

    for item, value in data.items():
        new_item = dict(value)
        class_item = new_item.pop('class')

        if class_item == 'static':
            template_static[item] = new_item
        elif class_item == 'dynamic':
            new_paths = glob.glob(item.replace("!(local)", "*"))
            for new_path in new_paths:
                if "diff/local/" not in new_path and not new_path.endswith('diff/local'):
                    template_dynamic[new_path] = new_item

    return template_static, template_dynamic

# ---------------------------------------------------------------------------------------------------------------


"""
    Remove items you want to ignore

    Parameters:
        - items: Dictionary with all the elements you want to filter
        - ignore_keys: List of all filenames or directories you want to ignore

    Return:
        Returns a dictionary without the ignored elements
"""


def cut_items(items: dict, ignore_keys: list = []) -> tuple[dict, list]:
    # Always ignore node_modules/
    ignore_keys.append('/var/ossec/api/node_modules')
    ignore_keys.append('/var/ossec/framework/python')

    ignore_keys = set(key.strip().lower() for key in ignore_keys)
    # Get all the files that matches the ignore_keys
    ignore_files = [k for k in items if any(i in k.lower() for i in ignore_keys)]
    new_items = {k: v for k, v in items.items() if k not in ignore_files}

    return new_items, ignore_files


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-t", "--target", type=str, required=True,
                            choices=['manager', 'agent'], help="Check files for manager or agent.")
    arg_parser.add_argument("-a", "--test", type=str, required=True,
                            choices=['upgrade', 'uninstall'], help="Type of test")
    arg_parser.add_argument("-v", "--version", type=str,
                            required=True, help="Check files for version: 2.0.1, etc.")
    arg_parser.add_argument("-o", "--os", type=str, required=True,  choices=[
                            'linux', 'windows', 'redhat', 'debian'], help="Operating system or host distribution")
    arg_parser.add_argument("-i", "--ignore", type=str,
                            help="Ignore path: /var/ossec/wodles/oscap/content,/var/ossec/api.")
    arg_parser.add_argument("-n", "--no_show_ignore_list",
                            action="store_true", help="No show ignore list")
    arg_parser.add_argument("-d", "--directory", type=str,
                            default="/var/ossec", help="Change OSSEC directory")
    arg_parser.add_argument("-f", "--from_version", type=str, default="",
                            help="Version you come from, to exclude files of it")
    args = arg_parser.parse_args()

    try:
        print(str(args))
        print("Checking files...")

        ignored_names = []
        missing_names = []
        extra_names = []
        different_names = []
        from_version = args.from_version
        version = args.version
        target = args.target
        test = args.test

        template_path = '{0}_{1}_check_files.json'.format(args.os, args.test)
        exceptions_data = read_exception_data(version, target)

        if args.directory:
            OSSEC_PATH = '{0}'.format(args.directory)

        if args.ignore:
            ignore_names = args.ignore.split(',')

        # Get data
        static_items, dynamic_items = get_template_items(template_path, version, target)
        current_items = get_current_items(OSSEC_PATH, ignore_names)

        if args.ignore:
            static_items, ignored_names_1 = cut_items(
                static_items, ignore_names)
            dynamic_items, ignored_names_2 = cut_items(
                dynamic_items, ignore_names)
            current_items, ignored_names_3 = cut_items(
                current_items, ignore_names)
            ignored_names.extend(ignored_names_1)
            ignored_names.extend(ignored_names_2)
            ignored_names.extend(ignored_names_3)

        # HARDCODED: Always ignore /var/ossec/api/node_modules/
        current_items, ignored_names_4 = cut_items(
            current_items, ['/var/ossec/api/node_modules/'])

        static_names = static_items.keys()
        dynamic_names = dynamic_items.keys()
        current_names = current_items.keys()

        # Missing files/directories
        missing_names = set(static_names) - set(current_names)

        # Extra files/directories
        extra_names_tmp = set(current_names) - set(static_names)
        check_extra_names = []
        for extra_name in extra_names_tmp:
            if extra_name in dynamic_names:
                check_extra_names.append(extra_name)
            else:
                extra_names.append(extra_name)

        # Different files/directories
        different_items = {}
        # Static
        for item in static_items:
            if item not in missing_names and static_items[item] != current_items[item]:
                different_names.append(item)
                different_items[item] = static_items[item]
        # Dynamic
        for check_extra_name in check_extra_names:
            if dynamic_items[check_extra_name] != current_items[check_extra_name]:
                different_names.append(check_extra_name)
                different_items[check_extra_name] = dynamic_items[check_extra_name]

        # Output
        different_names_output = ""
        for name in sorted(different_names):
            what = "Wrong: "
            if different_items[name]['user'] != current_items[name]['user']:
                what += " user"
            if different_items[name]['group'] != current_items[name]['group']:
                what += " group"
            if different_items[name]['mode'] != current_items[name]['mode']:
                what += " mode"

            different_names_output += "{0} [{1}]\n".format(name, what)
            different_names_output += "\tExpected: {0} {1}  {2}  # {3}\n".format(
                different_items[name]['user'], different_items[name]['group'], different_items[name]['mode'], different_items[name]['prot'])
            different_names_output += "\tFound   : {0} {1}  {2}  # {3}\n\n".format(
                current_items[name]['user'], current_items[name]['group'], current_items[name]['mode'], current_items[name]['prot'])

        extra_names_output = ""
        for name in sorted(extra_names):
            item_extra = get_data(name)
            extra_names_output += "{0}  [{1} {2} {3} {4}]\n".format(
                name, item_extra['user'], item_extra['group'], item_extra['mode'], item_extra['prot'])

        if ignored_names and not args.no_show_ignore_list:
            print("\nIgnored:")
            print('\n'.join(sorted(set(ignored_names))))

        if missing_names:
            print(
                "\nMissing (They are present in the check-files but they are not installed):")
            print('\n'.join(sorted(missing_names)))

        if extra_names:
            print("\nExtra (Not present in the check-files but they are installed):")
            print(extra_names_output)

        if different_names:
            print("\nDifferent:")
            print(different_names_output)

        if missing_names or extra_names or different_names:
            print("\nPlease, review your files.")
            sys.exit(1)
        else:
            print("\nCongrats!.")

    except Exception as e:
        print("Error: {0}".format(str(e)))
        raise
        sys.exit(1)
