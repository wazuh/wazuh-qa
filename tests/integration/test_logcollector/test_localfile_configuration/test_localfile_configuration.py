# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
from typing_extensions import ParamSpec
import pytest
import sys
import wazuh_testing.api as api
from wazuh_testing.tools import get_service
from wazuh_testing.tools.configuration import get_wazuh_conf, load_wazuh_configurations, write_wazuh_conf
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, WINDOWS_AGENT_DETECTOR_PREFIX
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.services import check_daemon_status, check_if_process_is_running, control_service
from wazuh_testing.tools import WAZUH_PATH

from deps.wazuh_testing.wazuh_testing.qa_ctl import configuration
from deps.wazuh_testing.wazuh_testing.vulnerability_detector import check_if_modulesd_is_running

tested_daemon = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
# test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
conf_path = os.path.join(WAZUH_PATH, 'ossec.conf') if sys.platform == 'win32' else \
    os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')

invalid_config = {
    'option': 'log_format',
    'values': 'syslog'
}

@pytest.fixture(scope="module", params=[invalid_config])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def add_localfile_conf(get_configuration):
    option, values = [get_configuration["option"], get_configuration["values"]]
    section_spaces = '  '
    option_spaces = '    '

    with open(conf_path, "r") as sources:
        lines = sources.readlines()

    with open(conf_path, 'w+') as sources:
        stop_search = False
        for line in lines:
            sources.write(line)
            if re.search(r'<\/localfile>', line) and not stop_search:
                sources.write(f'\n{section_spaces}<localfile>\n{option_spaces}<{option}>{values}</{option}>\n{section_spaces}</localfile>\n')
                stop_search = True

def test_invalid_configuration(get_configuration):
    # Save current configuration
    backup_config = get_wazuh_conf()
    #add invalid configuration to ossec.conf
    add_localfile_conf(get_configuration)
    #check daemon status without restart
    check_daemon_status(target_daemon=tested_daemon, running_condition=True)

    # restart daemon
    restart=True
    try:
        control_service('restart', tested_daemon)

    except:
        restart=False
        check_daemon_status(target_daemon=tested_daemon, running_condition=False)
        # check logs

        # Restore previous configuration
        write_wazuh_conf(backup_config)
        control_service('restart')

    if restart==True:
        write_wazuh_conf(backup_config)
        raise ValueError('Unexpected Daemon restarted')