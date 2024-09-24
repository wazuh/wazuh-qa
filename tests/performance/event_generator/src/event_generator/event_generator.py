# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Event generator library.

This library includes classes for simulating log and file operation events, designed to test and
validate the functionality of monitoring systems. It enables the controlled generation of events
such as file modifications, creations, and deletions, as well as structured log output.

Classes:
    - EventGenerator: The abstract base class for all event generators. Requires subclasses
      to implement the `generate_event` method.
    - LogEventGenerator: Generates simulated log entries to a file, managing log rotation
      based on size constraints.
    - SyscheckEventGenerator: Simulates file system changes (create, modify, delete)
      and manages state across events.

The library provides a configurable environment for testing system responses to a variety
of file and log-related events.
"""


import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class EventGenerator(ABC):
    """Base class for generating simulation events.

    This class provides the foundational attributes and methods for generating events.
    Subclasses implement the `generate_event` method to specify the actual event
    generation logic based on the specific type of event being simulated.
    """
    def __init__(self, rate: int, path: str, operations: int):
        """Initialize the EventGenerator.

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

    @abstractmethod
    def _generate_event(self) -> None:
        """Generate an event. This method should be overridden by subclasses to produce specific types of events."""
        pass

    def start(self) -> None:
        """Begin generating events until the stop condition or operation count is met."""
        next_time = time.time()
        while not self.stop_event.is_set() and self.count < self.operations:
            self._generate_event()
            self.count += 1
            next_time += 1 / self.rate
            sleep_time = next_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def stop(self) -> None:
        """Stop the event generation by setting the stop event."""
        self.stop_event.set()


class LogEventGenerator(EventGenerator):
    """Subclass of EventGenerator specifically designed for generating log files at a specified rate."""

    def __init__(self, rate: int, path: str, operations: int,
                 max_file_size: float | None = None, template_path: str | None = None):
        """Initialize the LogEventGenerator subclass.

        Args:
            rate (int): The rate at which logs are generated per second.
            path (str): The filesystem path where logs will be written.
            operations (int): The total number of logs to generate before stopping.
            max_file_size (float): The maximum file size in megabytes before the log is rotated.
            template_path (str, optional): Path to a JSON template file for log formatting. Defaults to None.
        """
        super().__init__(rate, path, operations)
        self.max_file_size = self._convert_file_size(max_file_size) if max_file_size else None
        self.template_path = template_path
        if template_path:
            with open(template_path) as file:
                self.template = json.load(file)
        else:
            self.template = {
                "date": "{date}",
                "time": "{time}",
                "severity": "{severity}",
                "message": "{message}"
            }
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def _convert_file_size(self, size_mb: int) -> int:
        """Convert file size from megabytes to bytes.

        Args:
            size_mb (int): File size in megabytes.

        Returns:
            int: File size in bytes.
        """
        return size_mb * 1024 * 1024

    def _generate_event(self) -> None:
        """Generate and write a log event based on a predefined template or a simple default format."""
        try:
            self._write_log()
        except OSError as e:
            logging.error(f"Error writing to log file: {e}")
            if not self._retry_write():
                logging.error("Failed to write to log after several attempts.")
                self.stop()


    def _write_log(self) -> None:
        """Write a log entry to the file based on the current date and time."""
        current_time = datetime.now()
        log_data = {
            "date": current_time.strftime("%Y-%m-%d"),
            "time": current_time.strftime("%H:%M:%S.%f")[:-3],
            "severity": "INFO",
            "message": "This is a test log message"
        }
        log_entry = self._template_format(log_data)
        with open(self.path, "a") as log_file:
            log_file.write(log_entry + "\n")
        logging.info(f"Log event generated at {self.path}")

        # Check file size and manage if necessary
        if self.max_file_size and os.path.getsize(self.path) > self.max_file_size:
            self._rotate_log()

    def _template_format(self, data: dict[str, str]) -> str:
        """Format the log data based on the template provided during initialization.

        Args:
            data (dict): Dictionary containing log data.

        Returns:
            str: A formatted string based on the template.
        """
        template_str = json.dumps(self.template)
        for key, value in data.items():
            template_str = template_str.replace('{' + key + '}', value)
        return template_str

    def _rotate_log(self) -> None:
        """Truncate the log file when the size limit is exceeded."""
        with open(self.path, 'w'):
            pass  # Truncate the file
        logging.info(f"Log file exceeded size limit and was truncated: {self.path}")

    def _retry_write(self, max_retries: int = 3) -> bool:
        """Attempt to write the log file up to a maximum number of retries.

        Returns:
            bool: True if writing succeeded, False otherwise.
        """
        retry_count = 0
        while retry_count < max_retries:
            try:
                self._write_log()
                return True
            except OSError:
                retry_count += 1
                time.sleep(1)  # wait a bit before retrying
        return False


class SyscheckEventGenerator(EventGenerator):
    """Subclass of EventGenerator specifically designed for file creation, modification and deletion."""

    def __init__(self, rate: int, path: str, operations: int):
        """Initialize the SyscheckEventGenerator with specific parameters to simulate file system events.

        Args:
            rate (int): The rate at which file events are generated per second. Must be greater than zero.
            path (str): The base directory path where file events will occur.
            operations (int): The total number of file operations to perform.

        Raises:
            ValueError: If 'rate' is less than or equal to zero.
        """
        if rate <= 0:
            raise ValueError("Rate must be a positive integer")
        if operations <= 0:
            raise ValueError("Operations must be a positive integer")
        super().__init__(rate, path, operations)
        os.makedirs(self.path, exist_ok=True)  # Ensure the directory exists
        self.files = []
        self.operation_sequence = self._build_operation_sequence()
        self.sequence_index = 0

    def _build_operation_sequence(self) -> list:
        """Build a predefined sequence of operations based on the total number of operations.

        Returns:
            list: A list of operations to perform in order.
        """
        operations = []

        # Determine the number of create, modify, and delete operations
        num_actions = 3  # create, modify, delete
        base_ops_per_action = self.operations // num_actions
        leftover_ops = self.operations % num_actions

        # Assign leftover operations to modifications
        num_creates = base_ops_per_action
        num_modifies = base_ops_per_action + leftover_ops
        num_deletes = base_ops_per_action

        # Determine the number of files to create
        num_files = num_creates if num_creates > 0 else 1  # Ensure at least one file

        # Generate file names
        file_names = [f"{self.path}/test_file_{i}.txt" for i in range(num_files)]

        # Step 1: Create files
        for file_name in file_names:
            operations.append(('create', file_name))

        # Step 2: Modify files
        modify_ops_per_file = num_modifies // num_files
        leftover_modifies = num_modifies % num_files
        for i, file_name in enumerate(file_names):
            num_modifies_for_file = modify_ops_per_file
            if i < leftover_modifies:
                num_modifies_for_file += 1
            for _ in range(num_modifies_for_file):
                operations.append(('modify', file_name))

        # Step 3: Delete files
        for file_name in file_names:
            operations.append(('delete', file_name))

        return operations

    def _generate_event(self) -> None:
        """Perform the next operation in the predefined sequence."""
        if self.sequence_index >= len(self.operation_sequence):
            self.stop_event.set()  # Stop if we have completed all operations
            return

        action, file_name = self.operation_sequence[self.sequence_index]

        if action == 'create':
            self._create_file(file_name)
            self.files.append(file_name)  # Track created file
        elif action == 'modify':
            self._modify_file(file_name)
        elif action == 'delete':
            self._delete_file(file_name)
            self.files.remove(file_name)  # Remove from list after deletion

        self.sequence_index += 1

    def _create_file(self, file_path: str) -> None:
        """Create a new file and write initial content to it."""
        with open(file_path, 'w'):
            pass
        logging.info(f"Created file: {file_path}")

    def _modify_file(self, file_path: str) -> None:
        """Modify an existing file by appending new content."""
        if os.path.exists(file_path):
            with open(file_path, 'a') as f:
                f.write(f"Modified on {datetime.now().isoformat()}\n")
            logging.info(f"Modified file: {file_path}")
        else:
            logging.error(f"File not found for modification: {file_path}")

    def _delete_file(self, file_path: str) -> None:
        """Delete a file."""
        try:
            os.remove(file_path)
            logging.info(f"Deleted file: {file_path}")
        except FileNotFoundError:
            logging.error(f"File not found for deletion: {file_path}")

class EventGeneratorFactory:
    """Factory class for creating EventGenerator instances."""

    @staticmethod
    def create_event_generator(module_name: str, config: dict[str, Any]) -> EventGenerator:
        """Create and return an EventGenerator instance based on the module name and configuration.

        Args:
            module_name (str): The name of the module.
            config (dict): Configuration settings specific to the module.

        Returns:
            EventGenerator: An instance of the appropriate EventGenerator subclass.

        Raises:
            ValueError: If the module name is unsupported.
        """
        if module_name == "logcollector":
            return LogEventGenerator(**config)
        elif module_name == "syscheck":
            return SyscheckEventGenerator(**config)
        else:
            raise ValueError(f"Unsupported module: {module_name}")
