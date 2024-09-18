"""Logger instance shared by all the modules to track workflow."""

import logging

logger = logging.getLogger('wazuh-monitor')

logger.setLevel(logging.INFO)
