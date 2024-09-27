# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Logger instance shared by all the modules to track workflow."""


import logging

logger = logging.getLogger('wazuh-monitor')

logger.setLevel(logging.INFO)
