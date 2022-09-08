# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest

from wazuh_testing.tools.services import control_service
from wazuh_testing.tools import configuration
from wazuh_testing.tools.run_simulator import simulate_agent,syslog_simulator


@pytest.fixture(scope='function')
def set_wazuh_configuration_analysisd(configuration, set_wazuh_configuration, configure_local_internal_options_eps):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_eps (fixture): Set the local_internal_options.conf file.
    """
    yield


@pytest.fixture(scope='function')
def simulate_agent_function(request):
    """Fixture to run the script simulate_agent.py"""
    simulate_agent(request.param)

    yield


@pytest.fixture(scope='function')
def configure_wazuh_one_thread():
    """Fixture to configure the local internal options file to work with one thread."""
    local_internal_options = {'analysisd.event_threads': '1', 'analysisd.syscheck_threads': '1',
                              'analysisd.syscollector_threads': '1', 'analysisd.rootcheck_threads': '1',
                              'analysisd.sca_threads': '1', 'analysisd.hostinfo_threads': '1',
                              'analysisd.winevt_threads': '1', 'analysisd.rule_matching_threads': '1',
                              'analysisd.dbsync_threads': '1', 'remoted.worker_pool': '1'}

    # Backup the old local internal options
    backup_local_internal_options = configuration.get_wazuh_local_internal_options()

    # Add the new configuration to local internal options
    configuration.add_wazuh_local_internal_options(local_internal_options)

    yield

    # Backup the old local internal options cofiguration
    configuration.set_wazuh_local_internal_options(backup_local_internal_options)


@pytest.fixture(scope='session')
def load_wazuh_basic_configuration():
    """Load a new basic configuration to the manager"""
    # Reference paths
    DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
    CONFIGURATIONS_PATH = os.path.join(DATA_PATH, 'wazuh_basic_configuration')
    configurations_path = os.path.join(CONFIGURATIONS_PATH, 'ossec.conf')

    backup_ossec_configuration = configuration.get_wazuh_conf()

    with open(configurations_path, 'r') as file:
        lines = file.readlines()
    configuration.write_wazuh_conf(lines)

    yield

    configuration.write_wazuh_conf(backup_ossec_configuration)


@pytest.fixture(scope='function')
def syslog_simulator_function(request):
    """Fixture to run the script syslog_simulator.py"""
    syslog_simulator(request.param)

    yield
