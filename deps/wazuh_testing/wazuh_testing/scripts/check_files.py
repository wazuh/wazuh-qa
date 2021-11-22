# This program is used to check that all installation files (except ignored and exceptions) have the expected permissions, owner, group ...
# It is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import argparse
import os
import grp
import pwd
import stat
import sys
from collections import Counter


_filemode_list = [
    {
        stat.S_IFLNK : "l",
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


def get_filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'.
    Args:
       mode (int): st_mode field of a file or directory from os.stat_result (Example: 16893)
    Return:
        string: Permissions set '-rwxrwxrwx'
    Example:
        33204 --> -rw-rw-r--
    """
    file_permission = []
    for items in _filemode_list:
        for stat_flag, stat_value in items.items():
            if mode & stat_flag == stat_flag:
                file_permission.append(stat_value)
                break
        else:
            file_permission.append('-')
    return "".join(file_permission)


def get_data_information(item):
    """Get the checkfile data from a file or directory.
    Args:
        item (string): Filepath or directory.
    Return:
        dict: Dictionary with checkfile data.
    Example:
        '/var/ossec/active-response' -->
            {
                "group": "wazuh",
                "mode": "750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
            }
"""
    try:
        stat_info = os.stat(item)

        user = pwd.getpwuid(stat_info.st_uid)[0]
        group = grp.getgrgid(stat_info.st_gid)[0]
        mode = oct(stat.S_IMODE(stat_info.st_mode))
        mode_str = str(mode).replace('o', '')
        if len(mode_str) > 3:
            mode = mode_str[-3:]
        else:
            mode = mode_str
        protection = get_filemode(stat_info.st_mode)
        if os.path.isdir(item):
            type = "directory"
        else:
            type = "file"

        return {'group': group, 'mode': mode, 'type': type, 'user': user, 'prot': protection}

    except FileNotFoundError:
        return {'group': None, 'mode': None, 'type': None, 'user': None, 'prot': None}
    except OSError: #Permission denied
        pass


def get_current_items(path='/', ignore_folders=[]):
    """Get a dictionary with all checkfile information from all files and directories located in a specific path
    Args:
        path (string): Path to begin extract information.
        ignore_folders (list): Forders lists to be ignored
    Return:
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
    flag_no_file_detected = False
    for (dirpath, dirnames, filenames) in os.walk(path, followlinks=False):
        dirpath = remove_ending_bar_chars(dirpath)
        aux_dirpath = remove_initial_bar_chars(dirpath)
        path_list = Counter(aux_dirpath.split('/'))

        for item_ignored in ignore_folders:
            item_ignored = remove_initial_bar_chars(item_ignored)
            substract_folders = Counter(item_ignored.split('/')) - path_list

            if substract_folders == {}:
                flag_no_file_detected = True
                break
            else:
                flag_no_file_detected = False
        if not flag_no_file_detected:
            files_items_dict[dirpath] = get_data_information(dirpath)
            for filename in filenames:
                file_path = f'{dirpath}/{filename}'
                if not file_path.endswith('.pyc') and not file_path in ignore_folders:
                    files_items_dict[file_path] = get_data_information(file_path)
        flag_no_file_detected = False
    return files_items_dict


def remove_initial_bar_chars(path):
    """Remove "/" character in the beginning of a path in case exists
    Args:
        path (string): Path to be analized
    Return:
        string: Path without initial "/" character
    Example:
        - /home/user becomes home/user
    """
    if path[0] == '/':
        path=path[1:]    #[1:]remove 1st char
    return path


def remove_ending_bar_chars(path):
    """Remove "/" character in the the end of a path in case exists
    Args:
        path (string): Path to be analized
    Return:
        string: Path without ending "/" character
    Example:
        - /home/user becomes home/user
    """
    if path[len(path) - 1] == '/':
        path=path[:-1]    #[:-1]remove last char
    return path


def get_script_parameters():
    """Generate option atributes to the entry point
    Return:
        ArgumentParser: Atributes to the entry point
    """
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-p", "--path", type=str, required=False, default='/',
                            help="Path base to inspect files recursively")
    arg_parser.add_argument("-i", "--ignore", type=str, default='/var/ossec', help="")
    return arg_parser.parse_args()


if __name__ == "__main__":
    """Main function
    Execution example:
        python3 check_files.py -p '/home/fede/Downloads' -i '/var/ossec,/home/fede/Downloads/wazuh.json'
    """
    argument = get_script_parameters()

    try:
        print("Checking files...")

        template_file = f'check_files.json'
        original_path = argument.path
        ignore_folders = argument.ignore.split(',') if argument.ignore else []
        current_items = get_current_items(original_path, ignore_folders)

        dictArray = {}
        element_list = []
        description_list = []
        i = 0
        for name in sorted(current_items):
            id = i
            try:
                group =  current_items[name]['group']
            except TypeError:
                group = '-'
            try:
                mode = current_items[name]['mode']
            except TypeError:
                mode = '-'
            try:
                prot = current_items[name]['prot']
            except TypeError:
                prot = '-'
            try:
                type = current_items[name]['type']
            except TypeError:
                type = '-'
            try:
                user = current_items[name]['user']
            except TypeError:
                user = '-'

            description_list.append({
                "group": group,
                "mode": mode,
                "prot": prot,
                "type": type,
                "user": user
            })

            element_list.append({
                "id": i,
                "name": name,
                "description" : description_list[i]
            })
            i = i + 1
        dictArray = {"data" : element_list}
        with open(template_file, 'w') as convert_file:
            convert_file.write(json.dumps(dictArray, indent=4))
        if len(ignore_folders) > 0:
            print("\nIgnored:")
            print('\n'.join(sorted(set(ignore_folders))))
        print("\nCongrats!.")

    except Exception as e:
        print(f'Error: {str(e)}')
        raise
        sys.exit(1) 