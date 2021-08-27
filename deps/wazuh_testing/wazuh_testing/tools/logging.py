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

        self.__validate_parameters()
        self.__initialize_parameters()
        self.__default_config()

    def __validate_parameters(self):
        """Verify class parameters value"""
        if self.level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError('LOGGER level must be one of the following values: DEBUG, INFO, WARNING, ERROR, CRITICAL')

    def __initialize_parameters(self):
        """Set logger level, mapping the string into enum constant"""
        level_mapping = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }

        self.level = level_mapping[self.level]

    def __default_config(self):
        """Set default handler configuration"""
        formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s')
        self.logger.setLevel(self.level)

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
