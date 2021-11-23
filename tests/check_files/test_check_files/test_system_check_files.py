# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
from datetime import datetime
from deepdiff import DeepDiff

from wazuh_testing.tools.file import validate_json_file, read_json_file, write_json_file

OUTPUT_FILE = f"system_checkfiles_{datetime.now().timestamp()}.json"


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


def test_system_check_files(get_first_file, get_second_file, get_output_path):
    """This test checks if two files are not equal.

    After an installation, update or uninstallation is necessary to check if the system files are the same as before.
    Two given files are checked for differences between them. After checking their contents, if there are differences
    between them, the test will fail and a log specifying the differences will be printed in JSON format. If the user
    specifies an output path, it will be saved there instead.

    Args:
        get_first_file (fixture): Get the file before making any changes to the environment.
        get_second_file (fixture): Get the file after making any changes to the environment.
        get_output_path (fixture): Get the output path where the result will be saved.
    """
    file1_data = validate_and_read_json(get_first_file)
    file2_data = validate_and_read_json(get_second_file)

    # The DeepDiff module gives us the differences between these two files.
    differences = DeepDiff(file1_data, file2_data)

    # We need to change the format of the key that DeepDiff provides, so it is most descriptive
    # Given difference key example:
    # "root['/home/jmv74211/Documents/trash/t/test_check_files/dockerfiles/ubuntu_20_04/entrypoint.py']['mode']"
    # Result: /home/jmv74211/Documents/trash/t/test_check_files/dockerfiles/ubuntu_20_04/entrypoint.py - mode"
    differences_str = differences.to_json().replace('][', ' - ').replace('root[', '').replace(']', '') \
                                           .replace('[', '')
    # If there are differences between the given files
    if differences != {}:
        # If the user specified an output path, the differences are saved in JSON format
        if get_output_path:
            output_path = os.path.join(get_output_path, OUTPUT_FILE)
            write_json_file(output_path, json.loads(differences_str))
            assert False, f"The given files are not equal, check the diff within {output_path}"
        # If the user did not specify an output path, the differences are printed in JSON format
        else:
            assert False, 'The given files are not equal, these are the diff:\n' \
                          f"{json.dumps(json.loads(differences_str), indent=4)}"
