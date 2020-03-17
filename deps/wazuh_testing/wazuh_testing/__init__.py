# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import sys
from collections import defaultdict


class Parameters:
    """Class to allocate all global parameters for testing"""

    def __init__(self):
        timeouts = defaultdict(lambda: 10)
        timeouts['linux'] = 5
        timeouts['darwin'] = 5
        self._default_timeout = timeouts[sys.platform]
        self._fim_database_memory = False

    @property
    def default_timeout(self):
        """
        Getter method for the default timeout property

        Returns
        -------
        int representing the default timeout in seconds
        """
        return self._default_timeout

    @default_timeout.setter
    def default_timeout(self, value):
        """
        Setter method for the default timeout property

        Parameters
        ----------
        value : int
            New value for the default timeout. Must be in seconds.
        """
        self._default_timeout = value

    @property
    def fim_database_memory(self):
        """
        Getter method for the fim_database_memory property

        Returns
        -------
        boolean representing if `fim_database_memory` is activated
        """
        return self._fim_database_memory

    @fim_database_memory.setter
    def fim_database_memory(self, value):
        """
        Setter method for the `fim_database_memory` property

        Parameters
        ----------
        value : bool
            New value for the `fim_database_memory`.
        """
        self._fim_database_memory = value

    @property
    def current_configuration(self):
        """
        Getter method for the current configuration property

        Returns
        -------
        dict
            A dictionary containing the current configuration.
        """
        return self._current_configuration

    @current_configuration.setter
    def current_configuration(self, value):
        """
        Setter method for the current configuration property

        Parameters
        ----------
        value : dict
            New value for the currenct configuration.
        """
        self._current_configuration = value

global_parameters = Parameters()
logger = logging.getLogger('wazuh_testing')
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
