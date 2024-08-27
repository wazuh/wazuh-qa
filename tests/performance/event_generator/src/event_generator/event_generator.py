# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Event generator library.

This library includes classes for simulating log and file operation events, designed to test and
validate the functionality of monitoring systems. It enables the controlled generation of events
such as file modifications, creations, and deletions, as well as structured log output.

Classes:
    - EventGenerator: The abstract base class for all event generators. Requires subclasses to implement
      the `generate_event` method.
    - LogEventGenerator: Generates simulated log entries to a file, managing log rotation based on size constraints.
    - SyscheckEventGenerator: Simulates file system changes (create, modify, delete) and manages state across events.

The library provides a configurable environment for testing system responses to a variety of file and log-related events.
"""

import json
from datetime import datetime
import os
import random
import threading
import time


class EventGenerator:
    def __init__(self, rate, path, operations):
        """
        Initialize the EventGenerator with a specific event generation rate, path for event storage and total number of operations.

        Args:
            rate (int): The rate at which events are generated per second.
            path (str): The filesystem path where events will be stored or handled.
            operations (int): The total number of events to generate before stopping.
        """
        self.rate = rate  # events per second
        self.path = path
        self.operations = operations
        self.stop_event = threading.Event()
        self.count = 0  # counter for events

    def generate_event(self):
        """
        Generate an event. This method should be overridden by subclasses to produce specific types of events.

        Raises:
            NotImplementedError: If the subclass does not override this method.
        """
        raise NotImplementedError(
            "This method should be overridden by subclasses.")

    def start(self):
        """
        Begin generating events at the specified rate until the stop condition is met or the operation count is reached.
        """
        next_time = time.time() + 1 / self.rate
        while not self.stop_event.is_set() and self.count < self.operations:
            self.generate_event()
            self.count += 1
            next_time += 1 / self.rate
            sleep_time = next_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def stop(self):
        """
        Stop the event generation by setting the stop event.
        """
        self.stop_event.set()


class LogEventGenerator(EventGenerator):
    """
    Subclass of EventGenerator specifically designed for generating log files at a specified rate.
    """

    def __init__(self, rate, path, operations, max_file_size=10, template_path=None):
        """
        Initialize the LogEventGenerator subclass with parameters for rate, path, operations, file size limit, and optional template path.

        Args:
            rate (int): The rate at which logs are generated per second.
            path (str): The filesystem path where logs will be written.
            operations (int): The total number of logs to generate before stopping.
            max_file_size (int): The maximum file size in megabytes before the log is rotated.
            template_path (str, optional): Path to a JSON template file for log formatting. Defaults to None.
        """
        super().__init__(rate, path, operations)
        self.max_file_size = max_file_size * 1024 * 1024  # Convert MB to bytes
        self.template_path = template_path
        if template_path:
            with open(template_path, 'r') as file:
                self.template = json.load(file)
        else:
            self.template = {
                "date": "{date}",
                "time": "{time}",
                "severity": "{severity}",
                "message": "{message}"
            }

    def generate_event(self):
        """
        Generate and write a log event based on a predefined template or a simple default format.
        """
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        try:
            self.write_log()
        except IOError as e:
            print(f"Error writing to log file: {e}")
            if not self.retry_write():
                print("Failed to write to log after several attempts.")

        time.sleep(1)  # Sleep to simulate delay between logs

    def write_log(self):
        """
        Write a log entry to the file based on the current date and time.
        """
        current_time = datetime.now()
        log_data = {
            "date": current_time.strftime("%Y-%m-%d"),
            "time": current_time.strftime("%H:%M:%S"),
            "severity": "INFO",
            "message": "This is a test log message"
        }
        log_entry = self.template_format(log_data)
        with open(self.path, "a") as log_file:
            log_file.write(log_entry + "\n")
        print("Log event generated at", self.path)

        # Check file size and manage if necessary
        if os.path.getsize(self.path) > self.max_file_size:
            self.rotate_log()

    def template_format(self, data):
        """
        Format the log data based on the template provided during initialization.

        Args:
            data (dict): Dictionary containing log data.

        Returns:
            str: A formatted string based on the template.
        """
        template_str = json.dumps(self.template)
        for key, value in data.items():
            template_str = template_str.replace('{' + key + '}', value)
        return template_str

    def rotate_log(self):
        """
        Rotate the log file when the size limit is exceeded.
        This creates a new log file by appending a sequence number or timestamp to the filename.
        """
        import time
        timestamp = int(time.time())  # Timestamp for uniqueness
        new_path = f"{self.path}_{timestamp}.old"
        os.rename(self.path, new_path)
        self.path = self.path.replace(
            ".log", f"_{timestamp}.log")  # Reset to new log file
        open(self.path, 'w').close()  # Create a new log file
        print(f"Log file exceeded size limit, rotated to {new_path}")

    def retry_write(self):
        """
        Attempt to write the log file up to a maximum number of retries.

        Returns:
            bool: True if writing succeeded, False otherwise.
        """
        retry_count = 0
        max_retries = 3
        while retry_count < max_retries:
            try:
                self.write_log()
                return True
            except IOError:
                retry_count += 1
                time.sleep(1)  # wait a bit before retrying
        return False


class SyscheckEventGenerator(EventGenerator):
    """
    Subclass of EventGenerator specifically designed for file creation, modification and deletion.
    """

    def __init__(self, rate, path, operations):
        """
        Initialize the SyscheckEventGenerator with specific parameters to simulate file system events.

        Args:
            rate (int): The rate at which file events are generated per second. Must be greater than zero.
            path (str): The base directory path where file events will occur.
            operations (int): The total number of file operations to perform.

        Raises:
            ValueError: If 'rate' is less than or equal to zero.
        """
        if rate <= 0:
            raise ValueError("Rate must be a positive integer")
        super().__init__(rate, path, operations)
        os.makedirs(self.path, exist_ok=True)  # Ensure the directory exists
        self.files = []  # List to keep track of created or modified files

    def generate_event(self):
        """
        Randomly generate file creation, modification, or deletion events at the specified path.
        """
        if not self.files or random.choice(['create', 'modify']) == 'create':
            action = 'create'
        else:
            action = random.choice(['modify', 'delete'])

        file_name = f"{self.path}/test_file_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.txt"

        if action == 'create':
            self.create_file(file_name)
            self.files.append(file_name)  # Track created file
        elif action == 'modify':
            file_name = random.choice(self.files)  # Choose a file to modify
            self.modify_file(file_name)
        elif action == 'delete':
            file_name = random.choice(self.files)  # Choose a file to delete
            self.delete_file(file_name)
            self.files.remove(file_name)  # Remove from list after deletion

    def create_file(self, file_path):
        """
        Create a new file and write initial content to it.
        """
        with open(file_path, 'w') as f:
            f.write("This is a new test file.\n")
        print(f"Created file: {file_path}")

    def modify_file(self, file_path):
        """
        Modify an existing file by appending new content. If the file does not exist, it creates it.
        """
        with open(file_path, 'a') as f:
            f.write(f"Modified on {datetime.now().isoformat()}\n")
        print(f"Modified file: {file_path}")

    def delete_file(self, file_path):
        """
        Delete a file. If the file does not exist, it logs that fact.
        """
        try:
            os.remove(file_path)
            print(f"Deleted file: {file_path}")
        except FileNotFoundError:
            print(f"File not found: {file_path}")
