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

# def parse_multiline_log(logger, log_message):
#     """
#     Parses a multiline log message and logs it with the provided logger.

#     Args:
#         logger (logging.Logger): The logger instance.
#         log_message (str): The log message to parse and log.
#     """
#     for line in log_message.split('\n'):
#         if line:
#             parse_and_log(logger, line)

# # log_utils.py
# import logging
# import os
# import threading

# def setup_logger(name):
#     logger = logging.getLogger(name)
#     handler = logging.StreamHandler()
#     formatter = logging.Formatter('%(asctime)s [PID: %(process)d] [%(threadName)s] [%(levelname)s] %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)
#     logger.setLevel(logging.DEBUG)
#     return logger

# def parse_and_log(logger: logging.Logger, line: str, extra: dict = None):
#     # Parse the log message
#     try:
#         _, log_level, log_message = line.split('[', 2)
#         log_message = log_message.rstrip(']')
#     except ValueError:
#         log_message = line
#         log_level = 'DEBUG'

#     if log_level.strip().upper() == 'DEBUG':
#         logger.debug(log_message, extra=extra)
#     elif log_level.strip().upper() == 'INFO':
#         logger.info(log_message, extra=extra)
#     elif log_level.strip().upper() == 'WARNING':
#         logger.warning(log_message, extra=extra)
#     elif log_level.strip().upper() == 'ERROR':
#         logger.error(log_message, extra=extra)
