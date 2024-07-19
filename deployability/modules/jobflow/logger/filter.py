# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import threading


class ThreadIDFilter(logging.Filter):
    """
    A filter that uppercases the name of the log record.
    """
    def filter(self, record: str) -> bool:
        """
        Inject thread_id to log records.
        
        Args:
            record (LogRecord): The log record to filter.
        
        Returns:
            bool: True if the record should be logged, False otherwise.
        """
        record.thread_id = threading.get_native_id()
        return record
