# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import glob
import pytest
import subprocess

from wazuh_testing.fim import callback_audit_health_check, callback_audit_added_rule, \
    callback_audit_rules_manipulation, callback_audit_loaded_rule, callback_audit_connection, \
    callback_realtime_added_directory, LOG_FILE_PATH
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3')]
testdir1, testdir2, testdir3 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec*.conf')))
def get_ossec_configuration(request):
    return request.param


def test_audit_health_check(configure_environment, restart_wazuh):
    """Checks if the health check is passed."""
    wazuh_log_monitor.start(timeout=20, callback=callback_audit_health_check)


def test_added_rules(configure_environment, restart_wazuh):
    """Checks if the specified folders are added to Audit rules list."""

    events = wazuh_log_monitor.start(timeout=20, callback=callback_audit_added_rule, accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


def test_readded_rules(configure_environment, restart_wazuh):
    """Checks if the removed rules are added to Audit rules list."""

    # Remove added rules
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir1))
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir2))
    os.system("auditctl -W {0} -p wa -k wazuh_fim".format(testdir3))

    wazuh_log_monitor.start(timeout=20, callback=callback_audit_rules_manipulation)

    events = wazuh_log_monitor.start(timeout=10, callback=callback_audit_loaded_rule, accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


def test_readded_rules_on_restart(configure_environment, restart_wazuh):
    """Checks if the rules are added to Audit when it restarts."""

    # Restart Audit
    p = subprocess.Popen(["service", "auditd", "restart"])
    p.wait()

    wazuh_log_monitor.start(timeout=10, callback=callback_audit_connection)

    events = wazuh_log_monitor.start(timeout=30, callback=callback_audit_loaded_rule, accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)


def test_move_rules_realtime(configure_environment, restart_wazuh):
    """Checks if the rules are changed to realtime when Audit stops."""

    # Stop Audit
    p = subprocess.Popen(["service", "auditd", "stop"])
    p.wait()

    events = wazuh_log_monitor.start(timeout=30, callback=callback_realtime_added_directory, accum_results=3).result()

    assert (testdir1 in events)
    assert (testdir2 in events)
    assert (testdir3 in events)

    # Start Audit
    p = subprocess.Popen(["service", "auditd", "start"])
    p.wait()
