import logging
import yaml


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
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f.read())
            logging.config.dictConfig(config)

    def get_logger(self) -> logging.Logger:
        """
        Returns the configured logger.

        Returns:
            logging.Logger: The configured logger.
        """
        return self.logger
