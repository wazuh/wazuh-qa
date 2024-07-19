# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import logging.config

from pathlib import Path

import yaml


def _load_config() -> None:
    """
    Loads the logging configuration from 'config.yaml' file.
    """
    config_path = Path(__file__).parent / 'config.yaml'
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)


_load_config()

logger = logging.getLogger("jobflow")
