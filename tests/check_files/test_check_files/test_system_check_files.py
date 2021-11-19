# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import pytest
from datetime import datetime
from deepdiff import DeepDiff

OUTPUT_FILE = f"system_checkfiles_{datetime.now().timestamp()}.json"


@pytest.fixture
def get_first_file(request):
    """Allows to use the --before-file in order to pass the file before an installation, update, or uninstallation.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption("--before-file")


@pytest.fixture
def get_second_file(request):
    """Allows to use the --after-file in order to pass the file after an installation, update, or uninstallation.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption("--after-file")


@pytest.fixture
def get_output_path(request):
    """Allows to use the --output-path so the users can save the output if they want.

    Args:
        request (fixture): Provide information on the executing test function.
    """
    return request.config.getoption("--output-path")


def test_system_check_files(get_first_file, get_second_file, get_output_path):
    """This test checks if two files are not equal.

    After an installation, update or uninstallation is necessary to check if the system files are the same as before.
    Two given files are checked for differences between them. After checking their contents, if there are differences
    between them, a log will be printed in JSON format. If the user specifies an output path, it will be saved there
    instead.

    Args:
        get_first_file (fixture): Get the file before the Wazuh installation/update/uninstallation
        get_second_file (fixture): Get the file after the Wazuh installation/update/uninstallation
        get_output_path (fixture): Get the output path where the output will be located.ç
    """
    with open(get_first_file) as json_file:
        file1_data = json.load(json_file)

    with open(get_second_file) as json_file:
        file2_data = json.load(json_file)

    # The DeepDiff module gives us the differences between these two files.
    diff = DeepDiff(file1_data, file2_data)

    # We need to change the format of the key that DeepDiff provides, so it is most descriptive
    # Given difference key example:
    # "root['/home/jmv74211/Documents/trash/t/test_check_files/dockerfiles/ubuntu_20_04/entrypoint.py']['mode']"
    # Result: /home/jmv74211/Documents/trash/t/test_check_files/dockerfiles/ubuntu_20_04/entrypoint.py - mode"
    json_str = diff.to_json().replace('][', ' - ').replace('root[', '').replace(']', '').replace("'", '') \
                             .replace('[', '')
    # If there are differences between the given files
    if diff != {}:
        # If the user did specify an output path, the differences are saved in JSON format
        if get_output_path:
            with open(os.path.join(get_output_path, OUTPUT_FILE), 'w+') as output_file:
                output_file.write(f"{json.dumps(json.loads(json_str), indent=4)}\n")
            assert False, f"The given files are not equal, check the diff within {get_output_path}"
        # If the user did not specify an output path, the differences are printed in JSON format
        else:
            assert False, "The given files are not equal, these are the diff:\n" \
                          f"{json.dumps(json.loads(json_str), indent=4)}"
