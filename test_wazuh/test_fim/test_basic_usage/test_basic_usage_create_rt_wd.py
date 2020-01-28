# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing.fim import (CHECK_ALL, DEFAULT_TIMEOUT, FIFO, LOG_FILE_PATH, REGULAR, SOCKET,
                               callback_detect_event, create_file, validate_event, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test

# Marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories + [os.path.join(PREFIX, 'noexists')])

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1, testdir2 = test_directories

# configurations

monitoring_modes = ['realtime', 'whodata']

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params, modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder', [
    testdir1,
    testdir2
])
@pytest.mark.parametrize('name, filetype, content, checkers, tags_to_apply, encoding', [
    ('file', REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file2', REGULAR, b'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('socketfile', REGULAR if sys.platform == 'win32' else SOCKET, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file3', REGULAR, 'Sample content', {CHECK_ALL}, {'ossec_conf'}, None),
    ('fifofile', REGULAR if sys.platform == 'win32' else FIFO, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file4', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, None),
    ('file-ñ', REGULAR, b'', {CHECK_ALL}, {'ossec_conf'}, None),
    pytest.param('檔案', REGULAR, b'', {CHECK_ALL}, {'ossec_conf'}, 'cp950', marks=(pytest.mark.linux,
                 pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('Образецтекста', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'koi8-r', marks=(pytest.mark.linux,
                 pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('Δείγμακειμένου', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'cp737', marks=(pytest.mark.linux,
                 pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('نصبسيط', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, 'cp720', marks=(pytest.mark.linux,
                 pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('Ξ³ΞµΞΉΞ±', REGULAR, '', {CHECK_ALL}, {'ossec_conf'}, None, marks=pytest.mark.win32)
])
def test_create_file_realtime_whodata(folder, name, filetype, content, checkers, tags_to_apply, encoding, get_configuration,
                                      configure_environment, restart_syscheckd, wait_for_initial_scan):
    """ Checks if a special or regular file creation is detected by syscheck using realtime and whodata monitoring

        Regular files must be monitored. Special files must not.

        :param folder: Name of the monitored folder
        :param name: Name of the file
        :param filetype: Type of the file
        :param content: Content of the file
        :param checkers: Checks that will compared to the ones from the event

        * This test is intended to be used with valid configurations files. Each execution of this test will configure
          the environment properly, restart the service and wait for the initial scan.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create files
    if encoding is not None:
        name = name.encode(encoding)
        folder = folder.encode(encoding)
    create_file(filetype, folder, name, content=content)

    if filetype == REGULAR:
        # Wait until event is detected
        event = wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event,
                                        encoding=encoding).result()
        validate_event(event, checkers)
    else:
        with pytest.raises(TimeoutError):
            wazuh_log_monitor.start(timeout=DEFAULT_TIMEOUT, callback=callback_detect_event)
