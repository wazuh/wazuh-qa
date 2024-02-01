import logging


class UppercaseNameFilter(logging.Filter):
    def filter(self, record):
        record.name = record.name.upper()
        return True
