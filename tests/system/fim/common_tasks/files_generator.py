# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import random
import string
import json
import platform
import subprocess


def generate_random_name(length):
    """ Generates random string of specified length (integer) """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def generate_folders_paths(root_path, recursion_level, folder_name_length, separator):
    """ Generates an array containing required subpaths """
    """ :param str root_path: The root folder, generated folders will hang from it """
    """ :param int recursion_level: Specifies the depth, folder '/root/test/' has depth 1 """
    """ :param str folder_name_length: Folder name length for every folder created """
    """ :param str separator: Either '\' or '/' used to separate paths """
    """ :return: Returns a list of paths """

    paths = []
    previous_folder = root_path

    for _ in range(recursion_level):  # _ designates an 'invisible' variable
        current_folder = previous_folder + separator + generate_random_name(folder_name_length)
        paths.append(current_folder)
        previous_folder = current_folder

    return paths


def create_folders(folders_path):
    """ Creates all required folders on Windows and Linux """
    """ :param dict folders_path: Dictionary with all folders paths """

    for folder in folders_path:
        try:
            subprocess.run(["mkdir", folder])
        except Exception:
            print("ERROR: Unable to create folder: " + folder + ". Aborting...")
            raise Exception


def generate_files_paths(folders_paths, n_files, file_name_length, separator):
    """ Generates files paths distributed among the folders paths """
    """ :param str folders_paths: Folders where files will be stored """
    """ :param int n_files: Number of file's paths to generate """
    """ :param str file_name_length: File name length for every file created """
    """ :param str separator: Either '\' or '/' used to separate paths """
    """ :return: Returns a list of paths """

    files_paths = []
    remaining_files = n_files

    for path in folders_paths:
        if (path == folders_paths[-1]):
            n_files_to_generate = remaining_files
        else:
            n_files_to_generate = random.randint(1, remaining_files)
        for _ in range(n_files_to_generate):
            current_file = path + separator + generate_random_name(8)
            files_paths.append(current_file)
        remaining_files = remaining_files - n_files_to_generate
    return files_paths


def parse_files_configuration(files_configuration_path):
    """ Converts a list object to a json object """
    """ :param list files_configuration_path: Path to the JSON configuration file """
    """ :return: Returns a dictionary of the parsed configuration"""
    with open(files_configuration_path, "r") as json_data:
        configuration_dict = json.load(json_data)
    return configuration_dict


def associate_files_size(files_paths, files_size_specifications):
    """ Takes the files paths and converts them into json assigning a file size """
    """ The key of every entry designates the path and the value the file size """
    """ :param dict files_paths: Contains the files paths """
    """ :param dict files_specification: Contains the files size specifications """
    """ :return: Returns a dictionary with the files and their associated size"""

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
    """ Takes the files paths and creates a file of specified size """
    """ :param dict files_path: Contains the list of files and it's associated path """
    """ :return: Returns a dictionary with the files and their associated size """
    if (platform.system() == "Linux"):
        for key, value in files_path.items():
            subprocess.run(["dd", "if=/dev/zero", "of=" + key, "bs=" + value, "count=1"])

    elif (platform.system() == "Windows"):
        for key, value in files_path.items():
            subprocess.run(["fsutil", "file", "createnew", key, value])
    else:
        print("Platform not supported")
        raise Exception


def main():
    config = parse_files_configuration("files_configuration.json")
    folders = generate_folders_paths(
                                        config["root_folder"],
                                        config["recursion_level"],
                                        config["folder_length"],
                                        config["separator"]
                                    )
    create_folders(folders)
    files = generate_files_paths(
                                        folders,
                                        config["number_of_files"],
                                        config["file_length"],
                                        config["separator"]
                                )
    associated_files = associate_files_size(files, config["file_size_specifications"])
    create_files(associated_files)


if __name__ == '__main__':
    main()
