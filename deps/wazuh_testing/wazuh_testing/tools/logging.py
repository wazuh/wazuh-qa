import logging
import os


class Logging:
    """Class to handle modules logging. It is a wrapper class from logging standard python module.

    Args:
        logger_name (str): Logger name
        level (str): Logger level: DEBUG, INFO, WARNING, ERROR or CRITICAL
        stdout (boolean): True for add stodut stream handler False otherwise
        log_file (str): True for add file handler, False otherwise
    Attributes:
        logger_name (str): Logger name
        level (str): Logger level: DEBUG, INFO, WARNING, ERROR or CRITICAL
        stdout (boolean): True for add stodut stream handler False otherwise
        log_file (str): True for add file handler, False otherwise
    """
    def __init__(self, logger_name, level='INFO', stdout=True, log_file=None):
        self.logger = logging.getLogger(logger_name)
        self.level = level
        self.stdout = stdout
        self.log_file = log_file

        self.update_configuration()

    def update_configuration(self):
        """Set default handler configuration"""
        if self.level == 'DEBUG':
            formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s')
        else:
            formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s')

        self.logger.setLevel(Logging.parse_level(self.level))

        # Remove old hadlers if exist
        self.logger.handlers = []

        if self.stdout:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if self.log_file:
            # Create folder path if not exist
            if not os.path.exists(os.path.dirname(self.log_file)):
                os.makedirs(os.path.dirname(self.log_file))

            handler = logging.FileHandler(self.log_file)
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    @staticmethod
    def __logger_exists(logger_name):
        """Get if logger exists or not.
        Returns:
            boolean: True if logger exists, false otherwise
        """
        return logger_name in logging.Logger.manager.loggerDict

    @staticmethod
    def get_logger(logger_name):
        """Get the logger object if exists

        Returns:
            logging.Logger: Logger object

        Raises:
            ValueError: If logger not exists

        """
        return logging.getLogger(logger_name)

    @staticmethod
    def parse_level(level):
        """Get logger level, mapping the string into enum constant

        Returns:
            int: Logger level (10 DEBUG - 20 INFO - 30 WARNING - 40 ERROR - 50 CRITICAL)

        Raises:
            ValueError if level is not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        """
        if level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError('LOGGER level must be one of the following values: DEBUG, INFO, WARNING, ERROR, CRITICAL')

        level_mapping = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }

        return level_mapping[level]

    def update_default_handlers(self, level='INFO', stdout=True, log_file=None):
        self.stdout = stdout
        self.log_file = log_file
        self.level = level

        self.update_configuration()

    def set_level(self, level):
        self.level = level
        self.logger.setLevel(Logging.parse_level(level))

    def enable(self):
        """Enable logger"""
        self.logger.disabled = False

    def disable(self):
        """Disable logger"""
        self.logger.disabled = True

    def debug(self, message):
        """Log DEBUG message"""
        self.logger.debug(message)

    def info(self, message):
        """Log INFO message"""
        self.logger.info(message)

    def warning(self, message):
        """Log WARNING message"""
        self.logger.warning(message)

    def error(self, message):
        """Log ERROR message"""
        self.logger.error(message)

    def critical(self, message):
        """Log CRITICAL message"""
        self.logger.critical(message)
