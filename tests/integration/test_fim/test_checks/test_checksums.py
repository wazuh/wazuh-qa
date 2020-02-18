# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

import pytest

from wazuh_testing import global_parameters
from wazuh_testing.fim import (CHECK_ALL, CHECK_MD5SUM, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SUM, LOG_FILE_PATH,
                               REQUIRED_ATTRIBUTES, regular_file_cud, generate_params)
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2'),
                    os.path.join(PREFIX, 'testdir3'), os.path.join(PREFIX, 'testdir4'),
                    os.path.join(PREFIX, 'testdir5'), os.path.join(PREFIX, 'testdir6'),
                    os.path.join(PREFIX, 'testdir7'), os.path.join(PREFIX, 'testdir8'),
                    os.path.join(PREFIX, 'testdir9'), os.path.join(PREFIX, 'testdir0')]
configurations_path = os.path.join(
    test_data_path, 'wazuh_checksums_windows.yaml' if sys.platform == 'win32' else 'wazuh_checksums.yaml')

testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

# configurations

p, m = generate_params()
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('path, checkers', [
    (testdir1, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir2, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM}),
    (testdir3, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM}),
    (testdir4, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA256SUM}),
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA1SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] -
     REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA1SUM} - {CHECK_SHA256SUM}),
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_ALL] -
     {CHECK_MD5SUM} - {CHECK_SHA1SUM} - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_SHA1SUM} - {CHECK_SHA256SUM}),
    (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA256SUM}),
    (testdir9, REQUIRED_ATTRIBUTES[CHECK_ALL] - {CHECK_MD5SUM} - {CHECK_SHA256SUM} - REQUIRED_ATTRIBUTES[CHECK_SUM]),
])
def test_checksums_checkall(path, checkers, get_configuration, configure_environment, restart_syscheckd,
                            wait_for_initial_scan):
    """
    Test the behaviour of check_all="yes" when using it with one or more check_sum options (checksum, sha1sum,
    sha256sum and md5sum) set to "no".

    Example:
        check_all="yes" check_sum="no"
        check_all="yes" check_sum="no" check_md5sum="no"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created and monitored.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_checksums_checkall'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')


@pytest.mark.parametrize('path, checkers', [
    (testdir1, REQUIRED_ATTRIBUTES[CHECK_SUM]),
    (testdir2, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM}),
    (testdir3, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA1SUM}),
    (testdir4, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA256SUM}),
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA1SUM}),
    (testdir5, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA1SUM} - {CHECK_MD5SUM}),
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA256SUM}),
    (testdir6, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA256SUM} - {CHECK_MD5SUM}),
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA1SUM} - {CHECK_SHA256SUM}),
    (testdir7, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA256SUM} - {CHECK_SHA1SUM}),
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_MD5SUM} - {CHECK_SHA256SUM}),
    (testdir8, REQUIRED_ATTRIBUTES[CHECK_SUM] - {CHECK_SHA256SUM} - {CHECK_MD5SUM})
])
def test_checksums(path, checkers, get_configuration, configure_environment, restart_syscheckd, wait_for_initial_scan):
    """
    Test the checksum options (checksum, sha1sum, sha256sum and md5sum)
    behaviour when is used alone or in conjunction.
    Check_all option will be set to "no" in order to avoid using the default check_all configuration.

    Example:
        check_all: "no" check_sum: "yes"
        check_all: "no" check_sum: "yes" check_md5sum: "no"
        ...

    Parameters
    ----------
    path : str
        Directory where the file is being created.
    checkers : dict
        Check options to be used.
    """
    check_apply_test({'test_checksums'}, get_configuration['tags'])

    regular_file_cud(path, wazuh_log_monitor, min_timeout=global_parameters.default_timeout, options=checkers,
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled')
