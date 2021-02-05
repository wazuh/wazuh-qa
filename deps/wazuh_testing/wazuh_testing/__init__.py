# Copyright (C) 2015-2021, Wazuh Inc.
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
        self._gcp_project_id = None
        self._gcp_subscription_name = None
        self._gcp_credentials_file = None
        self._gcp_topic_name = None
        self._fim_mode = None

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
        Getter method for the `fim_database_memory` property

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

    @property
    def gcp_project_id(self):
        """
        Getter method for the `gcp_project_id` property

        Returns
        -------
        str Google Cloud project id `gcp_project_id`.
        """
        return self._gcp_project_id

    @gcp_project_id.setter
    def gcp_project_id(self, value):
        """
        Setter method for the `gcp_project_id` property

        Parameters
        ----------
        value : string
            New value for the `gcp_project_id`.
        """
        self._gcp_project_id = value

    @property
    def gcp_subscription_name(self):
        """
        Getter method for the `gcp_subscription_name` property

        Returns
        -------
        str Google Cloud subscription name `gcp_subscription_name`.
        """
        return self._gcp_subscription_name

    @gcp_subscription_name.setter
    def gcp_subscription_name(self, value):
        """
        Setter method for the `gcp_subscription_name` property

        Parameters
        ----------
        value : string
            New value for the `gcp_subscription_name`.
        """
        self._gcp_subscription_name = value

    @property
    def gcp_credentials_file(self):
        """
        Getter method for the `gcp_credentials_file` property

        Returns
        -------
        str path of `gcp_credentials_file`.
        """
        return self._gcp_credentials_file

    @gcp_credentials_file.setter
    def gcp_credentials_file(self, value):
        """
        Setter method for the `gcp_credentials_file` property

        Parameters
        ----------
        value : string
            New value for the `gcp_credentials_file`.
        """
        self._gcp_credentials_file = value

    @property
    def gcp_topic_name(self):
        """
        Getter method for the `gcp_topic_name` property

        Returns
        -------
        str Google Cloud topic name `gcp_topic_name`.
        """
        return self._gcp_topic_name

    @gcp_topic_name.setter
    def gcp_topic_name(self, value):
        """
        Setter method for the `gcp_topic_name` property

        Parameters
        ----------
        value : string
            New value for the `gcp_topic_name`.
        """
        self._gcp_topic_name = value

    @property
    def fim_mode(self):
        """
        Getter method for the `fim_mode` property

        Returns
        -------
        list FIM modes that will be used.
        """
        return self._fim_mode

    @fim_mode.setter
    def fim_mode(self, value):
        """
        Setter method for the `fim_mode` property

        Parameters
        ----------
        value : list
            New value for the `fim_mode`.
        """
        self._fim_mode = value


global_parameters = Parameters()
logger = logging.getLogger('wazuh_testing')
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
