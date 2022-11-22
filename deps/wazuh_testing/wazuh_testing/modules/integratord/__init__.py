'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
from wazuh_testing.tools import ANALYSISD_DAEMON, DB_DAEMON, INTEGRATOR_DAEMON

# Variables
INTEGRATORD_PREFIX = INTEGRATOR_DAEMON
REQUIRED_DAEMONS = [INTEGRATOR_DAEMON, DB_DAEMON, ANALYSISD_DAEMON]
TIME_TO_DETECT_FILE = 2
