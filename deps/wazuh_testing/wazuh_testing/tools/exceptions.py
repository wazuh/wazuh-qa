
class QAValueError(Exception):
    def __init__(self, message, logger=None):
        self.message = message
        logger(message)
        super().__init__(self.message)
