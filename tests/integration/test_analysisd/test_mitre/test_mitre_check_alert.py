'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    Check if `analysisd` generates alerts enriching its fields with `MITRE` information.
    The objective consists on checking if `analysisd` can generate alerts using custom rules
    that contains the `mitre` field to enrich those alerts with MITREs IDs, techniques and tactics.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_analysisd/test_mitre/

daemons:
    - analysisd
    - syscheckd
    - wazuh-db

os_support:
    - linux, rhel5
    - linux, rhel6
    - linux, rhel7
    - linux, rhel8
    - linux, amazon linux 1
    - linux, amazon linux 2
    - linux, debian buster
    - linux, debian stretch
    - linux, debian wheezy
    - linux, ubuntu bionic
    - linux, ubuntu xenial
    - linux, ubuntu trusty
    - linux, arch linux

coverage:

pytest_args:

tags:

'''
import os

import jsonschema
import pytest
from wazuh_testing.mitre import (callback_detect_mitre_event, validate_mitre_event)
from wazuh_testing.tools import ALERT_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# variables

wazuh_alert_monitor = FileMonitor(ALERT_FILE_PATH)
_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

invalid_configurations = []

configurations = []
for i in range(1, 15):
    file_test = os.path.join(_data_path, f"test{i}.xml")
    configurations.append(file_test)
    if i in range(5, 9):
        invalid_configurations.append(file_test)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

def test_mitre_check_alert(get_configuration, configure_local_rules, restart_wazuh_alerts):
    '''
    description:
        Check if `MITRE` alerts are syntactically and semantically correct.

    wazuh_min_version:
        4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.

        - configure_local_rules:
            type: fixture
            brief: Configure a custom rule in `local_rules.xml` for testing.

        - restart_wazuh_alerts:
            type: fixture
            brief: Reset `alerts.json` and start a new monitor.

    assertions:
        - Check that the `MITRE` alerts are generated and that they are correct.

    test_input:
        Different test cases that are contained in external `XML` files (data directory)
        that include both valid and invalid rules for detecting `MITRE` events.

    logging:
        - ossec.log:
            - r".*Ossec server started.*"

        - alerts.json:
            -"Multiple alerts related to MITRE events."

    tags:

    '''
    # Wait until Mitre's event is detected
    if get_configuration not in invalid_configurations:
        event = wazuh_alert_monitor.start(timeout=30, callback=callback_detect_mitre_event).result()
        validate_mitre_event(event)
    else:
        with pytest.raises(jsonschema.exceptions.ValidationError):
            event = wazuh_alert_monitor.start(timeout=30, callback=callback_detect_mitre_event).result()
            validate_mitre_event(event)
