#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import os
import json
import random
import string
import secrets
import argparse
import time


def generate_random_name(length):
    """ Generates random string of specified length (integer) """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def generate_folders_paths(root_path, recursion_level, folder_name_length):
    """
    Generates an array containing required subpaths

    :param str root_path: The root folder, generated folders will hang from it
    :param int recursion_level: Specifies the depth, folder '/root/test/' has depth 1
    :param str folder_name_length: Folder name length for every folder created
    :return: Returns a list of paths
    """
    paths = []
    previous_folder = root_path
    for _ in range(recursion_level):  # _ designates an 'invisible' variable
        current_folder = os.path.join(previous_folder, generate_random_name(folder_name_length))
        paths.append(current_folder)
        previous_folder = current_folder
    return paths


def create_folders(folders_path):
    """
    Creates all required folders on Windows and Linux

    :param dict folders_path: Dictionary with all folders paths
    """
    for folder in folders_path:
        os.makedirs(folder, exist_ok=True)


def generate_files_paths(folders_paths, n_files, file_name_length, prefix="", ext_list=""):
    """
    Generates files paths distributed among the folders paths

    :param str folders_paths: Folders where files will be stored
    :param int n_files: Number of file's paths to generate
    :param str file_name_length: File name length for every file created
    :param str prefix: Add a prefix to the filename
    :param str ext_list: List of extensions
    :return: Returns a list of paths
    """
    files_paths = []
    remaining_files = n_files
    ext_list = ext_list.split()

    for path in folders_paths:
        if (path == folders_paths[-1]):
            n_files_to_generate = remaining_files
        else:
            n_files_to_generate = random.randint(1, remaining_files)
        for _ in range(n_files_to_generate):
            full_name = prefix + generate_random_name(8)
            current_file = os.path.join(path, full_name)
            files_paths.append(current_file)
        remaining_files = remaining_files - n_files_to_generate
    if ext_list:
        files_paths = [fpath + ".{}".format(random.choice(ext_list)) for fpath in files_paths]
    return files_paths


def parse_files_configuration(files_configuration_path):
    """
    Converts a list object to a json object

    :param list files_configuration_path: Path to the JSON configuration file
    :return: Returns a dictionary of the parsed configuration
    """
    with open(files_configuration_path, "r") as json_data:
        configuration_dict = json.load(json_data)
    return configuration_dict


def associate_files_size(files_paths, files_size_specifications):
    """
    Takes the files paths and converts them into json assigning a file size
    The key of every entry designates the path and the value the file size

    :param dict files_paths: Contains the files paths
    :param dict files_specification: Contains the files size specifications
    :return: Returns a dictionary with the files and their associated size
    """

    # Initialize all files size to 0
    files_with_associated_size = dict.fromkeys(files_paths, 0)

    for specification in files_size_specifications:
        # Getting items without a size assigned (size = 0)
        files_without_size = dict({k: v for k, v in files_with_associated_size.items() if v == 0})
        if (specification != files_size_specifications[-1]):
            selected_files = random.sample(list(files_without_size), k=specification["amount"])
        else:
            selected_files = files_without_size
        for selected_file in selected_files:
            files_with_associated_size[selected_file] = specification["size"]
    return files_with_associated_size


def create_files(files_path, text_mode=False, bunch_size=100, wait_time=1):
    """
    Takes the files paths and creates a file of specified size

    :param dict files_path: Contains the list of files and it's associated path
    :param bool text_mode: Create text files instead of binary
    """
    if text_mode:
        file_mode = "w"
        one_char = '0'
        chunk = (one_char * 1048576) + '\n'
        unique = generate_random_name
    else:
        file_mode = "wb"
        one_char = b'0'
        chunk = one_char * 1048577
        unique = secrets.token_bytes
    count = 0
    for key, value in files_path.items():
      if count >= bunch_size:
        time.sleep(wait_time)
        count = 0
      with open(key, file_mode) as f:
          count += 1
          if value > 1048576:
              nval = value // 1048576
              for val in range(nval):
                  f.write(chunk)
          else:
              f.write(one_char * value)
          f.write(unique(16))


def create_file_summary(files_path, logfile):
    """
    Creates a file that summarizes all the created files

    :param dict files_path: Contains the list of files and it's associated path
    :param str logfile: File to write the list of paths
    """
    if os.path.exists(logfile):
        os.remove(logfile)
    with open(logfile, 'w') as f:
        for path in files_path:
            f.write(path + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str, required=True,
                        dest="config", help="Configuration file")
    parser.add_argument("-o", '--output-list', type=str, required=True,
                        dest="output_list", help="List of generated files")
    parser.add_argument("-t", '--text-mode', default=False, action="store_true",
                        dest="text_mode", help="Create text files instead of binary"
                             " (default is False)")
    parser.add_argument("-p", '--prefix', type=str, default="",
                        dest="file_prefix", help="Add a common prefix to all filenames")
    parser.add_argument("-b", '--bunch-size', type=int, default=90,
                        dest="bunch_size", help="File generation bunch size")
    parser.add_argument("-w", '--wait-time', type=int, default=1,
                        dest="wait_time", help="Time interval between bunch generation (to avoid queue overflow)")
    parser.add_argument("--ext-list", type=str, default="",
                        dest="ext_list", help="Create files with these extensions")
    args = parser.parse_args()
    config_file = args.config
    output_file = args.output_list
    text_mode = args.text_mode
    prefix = args.file_prefix
    ext_list = args.ext_list
    config = parse_files_configuration(config_file)
    folders = generate_folders_paths(
        config["root_folder"],
        config["recursion_level"],
        config["folder_length"]
    )
    create_folders(folders)
    n_files = sum(x['amount'] for x in config['file_size_specifications'])
    files = generate_files_paths(
        folders, n_files, config["file_length"],
        prefix=prefix, ext_list=ext_list
    )
    associated_files = associate_files_size(files, config["file_size_specifications"])
    create_files(associated_files, text_mode=text_mode, bunch_size=args.bunch_size, wait_time=args.wait_time)
    create_file_summary(files, output_file)


if __name__ == '__main__':
    main()
