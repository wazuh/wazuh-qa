import sys


class QABaseException(Exception):
    def __init__(self, message, logger=None):
        self.message = f"\033[91m{message}\033[0m"
        if logger:
            logger(self.message)
            if logger.__name__ == 'debug':
                super().__init__(self.message)
            else:
                sys.exit(1)
        else:
            super().__init__(self.message)

class AnsibleException(QABaseException):
    def __init__(self, message, logger=None):
        super().__init__(message, logger)


class QAValueError(QABaseException):
    def __init__(self, message, logger=None):
        super().__init__(message, logger)
