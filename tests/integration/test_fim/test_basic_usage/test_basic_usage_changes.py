# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import CHECK_ALL, LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

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

conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__}
p, m = generate_params(extra_params=conf_params)
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
@pytest.mark.parametrize('name, encoding, checkers,  tags_to_apply', [
    ('regular0', None, {CHECK_ALL}, {'ossec_conf'}),
    pytest.param('檔案', 'cp950', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                    pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('Образецтекста', 'koi8-r', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                                pytest.mark.darwin,
                                                                                pytest.mark.sunos5)),
    pytest.param('Δείγμακειμένου', 'cp737', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                                pytest.mark.darwin,
                                                                                pytest.mark.sunos5)),
    pytest.param('نصبسيط', 'cp720', {CHECK_ALL}, {'ossec_conf'}, marks=(pytest.mark.linux,
                                                                        pytest.mark.darwin, pytest.mark.sunos5)),
    pytest.param('Ξ³ΞµΞΉΞ±', None, {CHECK_ALL}, {'ossec_conf'}, marks=pytest.mark.win32)

])
def test_regular_file_changes(folder, name, encoding, checkers, tags_to_apply,
                              get_configuration, configure_environment,
                              restart_syscheckd, wait_for_initial_scan):
    """
    Check if syscheckd detects regular file changes (add, modify, delete)

    Parameters
    ----------
    folder : str
        Directory where the files will be created.
    checkers : dict
        Syscheck checkers (check_all).
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    if encoding is not None:
        name = name.encode(encoding)
        folder = folder.encode(encoding)

    regular_file_cud(folder, wazuh_log_monitor, file_list=[name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, options=checkers, encoding=encoding,
                     triggers_event=True)
