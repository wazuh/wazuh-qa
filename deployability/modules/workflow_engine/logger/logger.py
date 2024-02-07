import logging
import logging.config
from pathlib import Path
import threading

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

logger = logging.getLogger("workflow_engine")

