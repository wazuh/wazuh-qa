# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from modules.allocation.generic.instance import Instance
from modules.allocation.generic.models import TrackOutput
from modules.generic.logger import Logger

# Default logger
logger = Logger("allocator").get_logger()


def logger_with_instance_name(instance_info: Instance | TrackOutput) -> logging.Logger:
    """
    Returns a logger with the instance name if it is different from the identifier,
    otherwise returns the default logger without the name.

    Args:
        instance (Instance): The instance object.

    Returns:
        logging.Logger: The logger object.
    """

    if instance_info.name != instance_info.identifier:
        return Logger(f"allocator [{instance_info.name}]").get_logger()
    return logger
