# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Configuration variables for mocking Wazuh manager services

This module defines default values and constants for generating and validating
mock JWT tokens in the context of Wazuh agent-manager communications. It also
includes other essential global parameters used for agent communication and management API services.
"""

DEFAULT_ISS = 'wazuh'
DEFAULT_AUD = 'Wazuh Agent comms API'
DEFAULT_EXPIRATION_TIME = 900
MANAGER_MOCK_TOKEN_SECRET_KEY = 'd028413fdddd9dcf49d4bc41e3b81c30a4b23218e88aaa6a1fe4c3341250d965'
