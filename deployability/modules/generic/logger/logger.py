# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import logging.config
import yaml

from pathlib import Path


class Logger:
    """
    A Logger class that configures and provides a logger using a configuration file.

    Attributes:
        logger (logging.Logger): The configured logger.
    """

    def __init__(self, name: str) -> None:
        """
        Initializes the Logger object.

        Args:
            name (str): The name of the logger.
        """
        self._load_config()
        self.logger = logging.getLogger(name)

    def _load_config(self) -> None:
        """
        Loads the logging configuration from 'config.yaml' file.
        """
        config_path = Path(__file__).parent / 'config.yaml'
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)

    def get_logger(self) -> logging.Logger:
        """
        Returns the configured logger.

        Returns:
            logging.Logger: The configured logger.
        """
        return self.logger
