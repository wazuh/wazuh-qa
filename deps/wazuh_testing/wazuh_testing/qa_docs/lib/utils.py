"""
brief: Wazuh DocGeneratot utils module
copyright: Copyright (C) 2015-2021, Wazuh Inc.
date: August 02, 2021
license: This program is free software; you can redistribute it
         and/or modify it under the terms of the GNU General Public
         License (version 2) as published by the FSF - Free Software Foundation.
"""

import os, shutil

from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging

utils_logger = Logging.get_logger(QADOCS_LOGGER)

def check_existance(source, key):
    """
        brief: Checks recursively if a key exists into a dictionary.
        args:
            - "source (dict): The source dictionary where the key should be found."
            - "key (string): The name of the key to look into the source dictionary."
    """
    if not isinstance(source, dict) and not isinstance(source, list):
        return False

    if key in source:
        return True
    elif isinstance(source, dict):
        for item in source:
            if check_existance(source[item], key):
                return True
        return False
    elif isinstance(source, list):
        for item in source:
            if check_existance(item, key):
                return True
        return False
    else:
        return False

def remove_inexistent(source, check_list, stop_list=None):
    """
        brief: Checks recursively if a source dictionary contains invalid keys that must be deleted.
        args:
            - "source (dict): The source dictionary where the key should be found."
            - "check_list (dict): Dictionary with all the valid keys."
            - "check_list (list): Keys where the recursive must finish"
    """
    for element in list(source):
        if stop_list and element in stop_list:
            break

        if not check_existance(check_list, element):
            del source[element]
        elif isinstance(source[element], dict):
            remove_inexistent(source[element], check_list, stop_list)

def get_keys_dict(_dic):
    """
        brief: Flat a dictionary into a list of its keys.
        args:
            - "_dic (dict): The source dictionary to be flattened."
    """
    keys = []
    for item in _dic:
        value = _dic[item]
        if isinstance(value, dict):
            result = get_keys_dict(value)
            keys.append({item : result})
        elif isinstance(value, list):
            result = get_keys_list(value)
            keys.append({item : result})
        else:
            keys.append(item)

    if len(keys) == 1:
        return keys[0]
    else:
        return keys

def get_keys_list(_list):
    """
        brief: Flat a list of dictionaries into a list of its keys.
        args:
            - "_list (list): The source list to be flattened."
    """
    keys = []
    for item in _list:
        if isinstance(item, dict):
            result = get_keys_dict(item)
            keys.append(result)
        elif isinstance(item, list):
            result = get_keys_list(item)
            keys.append(result)
        else:
            keys.append(item)

    if len(keys) == 1:
        return keys[0]
    else:
        return keys

def find_item(search_item, check):
    """
        brief: Search for a specific key into a list of dictionaries or values.
        args:
              - "search_item (string): The key to be found."
              - "check (list): A list of dictionaries or values where the key should be found."
        returns: None if the key couldn´t be found. The value of the finding.
    """
    for item in check:
        if isinstance(item, dict):
            list_element = list(item.keys())
            if search_item == list_element[0]:
                return list(item.values())[0]
        else:
            if search_item == item:
                return item

    return None

def check_missing_field(source, check):
    """
        brief: Checks recursively if a source dictionary contains all the expected keys.
        args:
            - "source (dict): The source dictionary where the key should be found."
            - "check (list): The expected keys."
    """
    missing_filed = None

    for source_field in source:
        if isinstance(source_field, dict):
            key = list(source_field.keys())[0]
            found_item = find_item(key, check)

            if not found_item:
                print(f"Missing key {source_field}")
                return key

            missing_filed = check_missing_field(source_field[key], found_item)

            if missing_filed:
                return missing_filed

        elif isinstance(source_field, list):
            missing_filed = None

            for check_element in check:
                missing_filed = check_missing_field(source_field, check_element)
                if not missing_filed:
                    break

            if missing_filed:
                return source_field
        else:
            found_item = find_item(source_field, check)

            if not found_item:
                print(f"Missing key {source_field}")
                return source_field

    return missing_filed

def clean_folder(folder):
    """
        brief: Completely cleans the content of a folder.
        args:
            - "folder (string): The path of the folder to be cleaned."
    """
    if not os.path.exists(folder):
        return

    utils_logger.debug(f"Going to clean '{folder}' folder")

    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)

        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            utils_logger.error(f"Failed to delete {file_path}. Reason: {e}")
