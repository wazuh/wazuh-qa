'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

# Services Variables
WAZUH_SERVICES_STOPPED = 'stopped'
WAZUH_SERVICE_PREFIX = 'wazuh'
WAZUH_SERVICES_STOP = 'stop'
WAZUH_SERVICES_START = 'start'

# Configurations
DATA = 'data'
WAZUH_LOG_MONITOR = 'wazuh_log_monitor'

# Marks Executions

TIER0 = pytest.mark.tier(level=0)
TIER1 = pytest.mark.tier(level=1)
TIER2 = pytest.mark.tier(level=2)

WINDOWS = pytest.mark.win32
LINUX = pytest.mark.linux
MACOS = pytest.mark.darwin
SOLARIS = pytest.mark.sunos5

AGENT = pytest.mark.agent
SERVER = pytest.mark.server
