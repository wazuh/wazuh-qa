import sys

from wazuh_testing.tools.logging import Logging


class QABaseException(Exception):
    def __init__(self, message, exception_name=None, logger=None, logger_name=None):
        self.message = f"\033[91m{message}\033[0m"
        if logger:
            logger(self.message) if exception_name == 'AnsibleException' else logger(message)
            logger_level = Logging.get_logger(logger_name).level

            # Disable exception traceback if logging level is not DEBUG
            sys.tracebacklimit = 0 if logger_level > 10 else 1000

            super().__init__() if exception_name == 'AnsibleException' else super().__init__(self.message)
        else:
            super().__init__(self.message)

class AnsibleException(QABaseException):
    def __init__(self, message, logger=None, logger_name=None):
        super().__init__(message, self.__class__.__name__, logger, logger_name)

class QAValueError(QABaseException):
    def __init__(self, message, logger=None, logger_name=None):
        super().__init__(message, self.__class__.__name__, logger, logger_name)
