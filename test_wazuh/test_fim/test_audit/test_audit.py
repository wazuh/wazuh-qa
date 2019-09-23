# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import subprocess

import pytest

from wazuh_testing.fim import (LOG_FILE_PATH, callback_audit_added_rule,
                               callback_audit_connection,
                               callback_audit_health_check,
                               callback_audit_loaded_rule,
                               callback_audit_rules_manipulation,
                               callback_realtime_added_directory)
from wazuh_testing.tools import FileMonitor


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = [
                  # config1
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'directories': {'value': '/testdir1,/testdir2,/testdir3',
                                                 'attributes': {'check_all': 'yes',
                                                                'whodata': 'yes'}}}
                                ],
                   'checks': {'config1'}}
                  ]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('checks', [
    ({'all'})
])
def test_audit_health_check(checks, get_configuration, configure_environment,
                            restart_wazuh):
    """Checks if the health check is passed."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_health_check)


@pytest.mark.parametrize('checks', [
    ({'all'})
])
def test_added_rules(checks, get_configuration, configure_environment,
                     restart_wazuh):
    """Checks if the specified folders are added to Audit rules list."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    events = wazuh_log_monitor.start(timeout=20,
                                     callback=callback_audit_added_rule,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


@pytest.mark.parametrize('checks', [
    ({'all'})
])
def test_readded_rules(checks, get_configuration, configure_environment,
                       restart_wazuh):
    """Checks if the removed rules are added to Audit rules list."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    # Remove added rules
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir1))
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir2))
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir3))

    wazuh_log_monitor.start(timeout=20,
                            callback=callback_audit_rules_manipulation)

    events = wazuh_log_monitor.start(timeout=10,
                                     callback=callback_audit_loaded_rule,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


@pytest.mark.parametrize('checks', [
    ({'all'})
])
def test_readded_rules_on_restart(checks, get_configuration,
                                  configure_environment, restart_wazuh):
    """Checks if the rules are added to Audit when it restarts."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    # Restart Audit
    p = subprocess.Popen(["service", "auditd", "restart"])
    p.wait()

    wazuh_log_monitor.start(timeout=10,
                            callback=callback_audit_connection)

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_audit_loaded_rule,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


@pytest.mark.parametrize('checks', [
    ({'all'})
])
def test_move_rules_realtime(checks, get_configuration, configure_environment,
                             restart_wazuh):
    """Checks if the rules are changed to realtime when Audit stops."""
    if not (checks.intersection(get_configuration['checks']) or
       'all' in checks):
        pytest.skip("Does not apply to this config file")

    # Stop Audit
    p = subprocess.Popen(["service", "auditd", "stop"])
    p.wait()

    events = wazuh_log_monitor.start(timeout=30,
                                     callback=callback_realtime_added_directory,
                                     accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)

    # Start Audit
    p = subprocess.Popen(["service", "auditd", "start"])
    p.wait()
