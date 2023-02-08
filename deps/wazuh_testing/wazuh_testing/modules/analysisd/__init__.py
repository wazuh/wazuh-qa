'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

from wazuh_testing.tools import ANALYSISD_DAEMON

# Variables
ANALYSISD_PREFIX = fr".+{ANALYSISD_DAEMON}"

# Callback Messages
CB_ANALYSISD_STARTUP_COMPLETED = r'.*DEBUG: Startup completed. Waiting for new messages.*'

# Error messages
ERR_MSG_STARTUP_COMPLETED_NOT_FOUND = fr"Did not recieve the expected '{CB_ANALYSISD_STARTUP_COMPLETED}'"
