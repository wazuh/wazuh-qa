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
import argparse


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


def generate_files_paths(folders_paths, n_files, file_name_length):
    """
    Generates files paths distributed among the folders paths

    :param str folders_paths: Folders where files will be stored
    :param int n_files: Number of file's paths to generate
    :param str file_name_length: File name length for every file created
    :return: Returns a list of paths
    """
    files_paths = []
    remaining_files = n_files

    for path in folders_paths:
        if (path == folders_paths[-1]):
            n_files_to_generate = remaining_files
        else:
            n_files_to_generate = random.randint(1, remaining_files)
        for _ in range(n_files_to_generate):
            current_file = os.path.join(path, generate_random_name(8))
            files_paths.append(current_file)
        remaining_files = remaining_files - n_files_to_generate
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


def create_files(files_path):
    """
    Takes the files paths and creates a file of specified size

    :param dict files_path: Contains the list of files and it's associated path
    """
    for key, value in files_path.items():
        with open(key, "wb") as f:
            f.write(b'0'*value)


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
            f.write(path+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('configuration', action="store")
    args = parser.parse_args()
    configuration = args.configuration
    config = parse_files_configuration(configuration)
    folders = generate_folders_paths(
                                        config["root_folder"],
                                        config["recursion_level"],
                                        config["folder_length"]
                                    )
    create_folders(folders)
    n_files = sum(x['amount'] for x in config['file_size_specifications'])
    files = generate_files_paths(folders, n_files, config["file_length"])
    associated_files = associate_files_size(files, config["file_size_specifications"])
    create_files(associated_files)
    create_file_summary(files, config['output_file'])


if __name__ == '__main__':
    main()
