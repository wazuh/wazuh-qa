# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from subprocess import Popen, PIPE, DEVNULL
import re
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, generate_params, create_file, REGULAR, callback_detect_event, \
                              callback_detect_delete_event
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]
directory_str = ','.join(test_directories)
for direc in list(test_directories):
    test_directories.append(os.path.join(direc, 'subdir'))
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories[2:]

# configurations

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
parameters, metadata = generate_params(extra_params=conf_params, modes=['whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# fixtures
@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.parametrize('folder, file_list, filetype, tags_to_apply', [
    (testdir1, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},),
    (testdir2, ['regular0', 'regular1', 'regular2'], REGULAR, {'ossec_conf'},)
])
def test_deferred_delete_file(folder, file_list, filetype, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_fim_start):
    """
    Check if syscheckd detects 'deleted' events from the files contained
    in a folder that are deleted in a deferred manner.

    We first run the command in order to find the confirmation character in the os,
    after that we delete the files

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    file_list : list
        Names of the files.
    filetype : str
        Type of the files that will be created.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files inside subdir folder
    for file in file_list:
        create_file(filetype, folder, file, content='')

    # Wait for the added events
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_event,
                            accum_results=len(file_list), error_message='Did not receive expected '
                            '"Sending FIM event: ..." event')

    # Delete the files under 'folder'
    command = 'del "{}"\n'.format(folder)

    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate(timeout=global_parameters.default_timeout)
    except TimeoutError:
        pass

    # Find the windows confirmation character
    confirmation = re.search(r'\((\w)\/\w\)\?', stdout[0])
    assert confirmation

    # Run the command again and confirm deletion of files
    cmd = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    try:
        stdout = cmd.communicate('{}\n'.format(confirmation.group(1)), timeout=global_parameters.default_timeout)
    except TimeoutError:
        pass

    # Start monitoring
    wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_detect_delete_event,
                            accum_results=len(file_list), error_message='Did not receive expected '
                            '"Sending FIM event: ..." event')
