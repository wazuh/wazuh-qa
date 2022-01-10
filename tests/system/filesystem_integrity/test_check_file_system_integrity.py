# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
import re
import warnings
from deepdiff import DeepDiff

from wazuh_testing.tools.file import validate_json_file, read_json_file, write_json_file, get_file_lines

WARNING_LIST_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'warning_list.txt')


@pytest.fixture
def get_first_file(request):
    """Allow to use the --before-file parameter in order to pass the file before making any changes to the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--before-file')


@pytest.fixture
def get_second_file(request):
    """Allow to use the --after-file parameter in order to pass the file after making any changes to the environment.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--after-file')


@pytest.fixture
def get_output_path(request):
    """Allow to use the --output-path parameter to store the test result in the specified file.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption('--output-path')


def read_warning_list(path):
    """Read the warning list content.

    Args:
        path (str): Path to the warning list file.

    Returns:
        warning_list (list): Paths from the warning list.
    """
    lines = get_file_lines(path)
    warning_list = []

    for line in lines:
        warning_list.append(line.replace('\n', ''))

    return warning_list


def validate_and_read_json(file_path):
    """Validate the JSON file passed as argument and return its content.

    Args:
        file_path (str): JSON file path.

    Returns:
        The JSON file content.

    Raises:
        ValueError: If the given file is not valid.
    """
    if validate_json_file(file_path):
        file_data = read_json_file(file_path)
    else:
        raise ValueError(f"The file {file_path} is not a valid JSON.")

    return file_data


def validate_and_create_output_path(output_path):
    """"Check that the given output path is a directory if it already exists and creates it when it does not exist yet.

    Args:
        output_path (str): Path that the user pass as argument.
    """
    try:
        if os.path.exists(output_path) and not os.path.isdir(output_path):
            raise ValueError(f"The given output path {output_path} already exists and is not a directory.")
    except TypeError:
        raise TypeError(f"The --output-path flag expects a string with the path where you want to save the test "
                        "results.")

    if not os.path.exists(output_path):
        os.makedirs(output_path)


def path_in_warning_list(path_to_check, warning_list):
    """Check if a path is contained in the warning list.

    It checks if the path is contained in each path from the warning list. If the path to check appears in the list or
    is a descendant, it will return True.

    Args:
        path_to_check (str): Path that will be checked.
        warning_list (list): Warning list that contains the paths to compare.

    Returns:
        boolean: True if the given path is contained in the warning list, False otherwise.
    """
    for path in warning_list:
        if path in path_to_check:
            return True

    return False


def copy_to_dict_and_reset(key, dict, data_structure):
    """Copy a data structure content into a dictionary using the given key.

    The given content to copy is cleared after its copy.

    Args:
        key (str): Dict key where the content will be copied.
        dict (dict): Where the data will be copied.
        data_structure (list|dict): Content to copy.
    """
    if data_structure:
        dict[key] = data_structure.copy()
        data_structure.clear()


def add_differences_to_dict(path, dict, field, value_changes):
    """Add the given values to a specific dictionary.

    Args:
        path (str): Path(dict key) to add or modify the dictionary with the given '{field: value}'
        dict (dict): Dictionary where the given '{field: value}' will be added.
        field (str): Field to be added. e.g. last_update, md5sum, size, etc.
        value_changes (str): Changes to be added. e.g. {"new_value": "2021-12-14 04:50:46",
                             "old_value": "2021-12-14 04:48:41"}
    """
    if path not in dict:
        dict[path] = {field: value_changes}
    else:
        dict[path][field] = value_changes


def move_misplaced_red(state, red_diff, yellow_diff):
    """Move the misplaced paths in the red state dictionary to yellow when it proceeds.

    If there is a path that its descendency is already in the yellow dict, it is moved from 'red' to 'yellow'.

    Args:
        state (str): Test state
        red_dict (dict): Dictionary with the differences to be checked.
        yellow_dict (dict): Dictionary with the knowing warning differences.

    Returns:
        move (boolean): True if there were changes in the red dictionary, False otherwise.
    """
    move = False
    break_loop = False
    to_move = []

    if state == 'red':
        for red_path in red_diff:
            for yellow_change_type in yellow_diff:
                for yellow_path in yellow_diff[yellow_change_type]:
                    if red_path in yellow_path:
                        to_move.append((red_path, red_diff[red_path]))
                        move = True
                        break_loop = True
                        # Iterates thru the next path in red diff
                        break

                if break_loop:
                    break_loop = False
                    break

    # Remove all the misplaced occurrences
    for path, values_changes in to_move:
        yellow_diff['values_changed'][path] = values_changes
        red_diff.pop(path, None)

    return move


def check_diffs_in_warning_list(diff, warning_list):
    """"Check if the given differences are contained in the warning list or not.

    Each possible state has a dictionary that contains the paths that have been changed, the related metadata and its
    old-new values changes. Every path that is listed in the warning list results in a instance within the dictionary
    related to warnings(yellow). If a path is not listed in the warning list, it is added to the red dictionary instead.

    Args:
        diff (dict): Differences between the given files.
        warning_list (list): Paths that are allowed to change but a manual revision is required.

    Returns:
        (state, yellow_dict, red_dict): 3-tuple with a boolean that represents if the test has a warning related to the
                                        warning list or it fails, and the states dictionaries.
    """
    # The following regex matches for example with:
    # "['/etc/mtab']['last_update']" and "['/usr/share/doc/openssl']"
    fields_regex = re.compile(r"\['(.+?)'\]+")
    state = 'yellow'
    yellow_matched_list = []
    red_matched_list = []
    yellow_matched_dict = {}
    red_matched_dict = {}
    yellow_output_dict = {}
    red_output_dict = {}

    for change_type in diff:
        if isinstance(diff[change_type], list):
            for path in diff[change_type]:
                matched_path = re.match(fields_regex, path).group(1)

                if path_in_warning_list(matched_path, warning_list):
                    yellow_matched_list.append(matched_path)
                else:
                    state = 'red'
                    red_matched_list.append(matched_path)

            # Clear the lists so they can be used if there are more keys that are a list within the differences
            copy_to_dict_and_reset(change_type, yellow_output_dict, yellow_matched_list)
            copy_to_dict_and_reset(change_type, red_output_dict, red_matched_list)

        if isinstance(diff[change_type], dict):
            # add key to matched dict, values changed is not

            for path_and_field in diff[change_type]:
                matched_fields = re.findall(fields_regex, path_and_field)
                matched_path = matched_fields[0]
                matched_field = matched_fields[1]
                values_changes = diff[change_type][path_and_field]

                if path_in_warning_list(matched_path, warning_list):
                    add_differences_to_dict(matched_path, yellow_matched_dict, matched_field, values_changes)
                else:
                    state = 'red'
                    add_differences_to_dict(matched_path, red_matched_dict, matched_field, values_changes)

            # Clear the dicts so they can be used if there are more keys that are a dict within the differences
            copy_to_dict_and_reset(change_type, yellow_output_dict, yellow_matched_dict)
            copy_to_dict_and_reset(change_type, red_output_dict, red_matched_dict)

    # If after moving the misplaced paths within the red diff, still there are red diffs the state is red
    # If there are no red diffs, that means that only wrong red diffs were in the red diff, so the state is
    # yellow
    if move_misplaced_red(state, red_output_dict['values_changed'], yellow_output_dict):
        if not red_output_dict['values_changed']:
            red_output_dict.pop('values_changed', None)
        if not red_output_dict:
            state = 'yellow'

    return state, yellow_output_dict, red_output_dict


def test_check_file_system_integrity(get_first_file, get_second_file, get_output_path):
    """This test checks if two files are not equal and if differences exist, and check if the path where are changes
    is listed in the warning list or not.

    After an installation, update or uninstallation is necessary to check if the system files are the same as before.
    Two given files are checked for differences between them. After checking their contents, if there are differences
    between them, the test will check if any of the paths that have changed is listed in the warning list(which would
    change the test state to 'warning', aka 'yellow') or not(which would change the test state to 'failed', aka 'red').
    These differences(a file for each state) will be stored in the path that the user passes as an argument.

    If the test shows a warning related to the differences, the state of the test exectuion requires a manual revision.

    The possible states after the test execution are:
        - yellow: When there are paths with changes but they appear in the warning list.
        - red: When there are paths with changes that do not appear in the warning list.

    Example run:
        python3 -m pytest wazuh-qa/tests/check_files/test_check_files/test_system_check_files.py
        --before-file initial_state --after_file after_installing_manager --output-path /tmp/system_check_files

    Args:
        get_first_file (fixture): Get the file before making any changes to the environment.
        get_second_file (fixture): Get the file after making any changes to the environment.
        get_output_path (fixture): Get the output path where the result will be saved.
    """
    file1_data = validate_and_read_json(get_first_file)
    file2_data = validate_and_read_json(get_second_file)
    validate_and_create_output_path(get_output_path)

    # The DeepDiff module gives us the differences between these two files.
    differences = DeepDiff(file1_data, file2_data)
    differences_str = differences.to_json().replace('root', '')

    # If there are differences between the given files
    if differences != {}:
        differences_json = json.loads(differences_str)
        test_state, yellos_json_dict, red_json_dict = check_diffs_in_warning_list(differences_json,
                                                                                  read_warning_list(WARNING_LIST_PATH))

        yellow_path = os.path.join(get_output_path, 'warning_diff.json')
        write_json_file(yellow_path, yellos_json_dict)
        warnings.warn("There are some directories that are contained in the warning list. "
                      f"Please check {yellow_path} file in order to determinate if the test passes "
                      "or not.", UserWarning)

        if test_state == 'red':
            red_path = os.path.join(get_output_path, 'fail_diff.json')
            write_json_file(red_path, red_json_dict)
            raise AssertionError("There are some directories that not contained within the warning list. "
                                 f"These paths are logged here: {red_path}.")
