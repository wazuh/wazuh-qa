# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh_testing import logger


def create_regular_file(path, name, content=''):
    """Create a regular file.

    Args:
        path (str): path where the regular file will be created.
        name (str): file name.
        content (str, optional): content of the created file. Default `''`
    """
    regular_path = os.path.join(path, name)
    mode = 'w+'
    try:      
        logger.info("Creating file " + str(os.path.join(path, name)) + " type")
        with open(regular_path, mode) as file:
            file.write(content)
    except OSError:
        logger.info("File could not be created.")
