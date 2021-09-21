
class AnsibleException(Exception):
    def __init__(self, message):
        super().__init__(message)

class QAValueError(Exception):
    def __init__(self, message, logger=None):
        self.message = f"\033[91m{message}\033[0m"
        logger(message)
        super().__init__(self.message)
