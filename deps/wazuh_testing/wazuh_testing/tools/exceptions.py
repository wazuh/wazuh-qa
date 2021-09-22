import sys

from wazuh_testing.tools.logging import Logging

class QABaseException(Exception):
    def __init__(self, message, logger=None, logger_name=None):
        self.message = f"\033[91m{message}\033[0m"
        if logger:
            logger(self.message)
            logger_level = Logging.get_logger(logger_name).level
            if logger_level == 10:  # DEBUG level
                super().__init__(self.message)
            else:
                sys.exit(1)
        else:
            super().__init__(self.message)

class AnsibleException(QABaseException):
    def __init__(self, message, logger=None, logger_name=None):
        super().__init__(message, logger, logger_name)


class QAValueError(QABaseException):
    def __init__(self, message, logger=None, logger_name=None):
        super().__init__(message, logger, logger_name)
