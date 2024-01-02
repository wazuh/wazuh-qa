# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from abc import ABC, abstractmethod
import subprocess
import logging
import random
import time


class Task(ABC):
    """Abstract base class for tasks."""

    @abstractmethod
    def execute(self) -> None:
        """Execute the task."""
        pass


class ProcessTask(Task):
    """Task for executing a process."""

    def __init__(self, task_name: str, task_parameters: dict, logger: logging.Logger):
        """
        Initialize ProcessTask.

        Args:
            task_name (str): Name of the task.
            task_parameters (dict): Parameters for the task.
            logger (logging.Logger): Logger instance.
        """
        self.task_name = task_name
        self.task_parameters = task_parameters
        self.logger = logger

    def execute(self) -> None:
        """Execute the process task."""

        # Function to format key:value elements
        def format_key_value(task_arg):
            key, value = list(task_arg.items())[0]
            return f"--{key}={value}"

        task_args = [str(task_arg) if isinstance(task_arg, str) else format_key_value(task_arg) for task_arg in self.task_parameters['args']]

        try:
            self.logger.info("ejecutando task ")
            self.logger.info(f"{[self.task_parameters['path']]+ task_args}")
            result = subprocess.run(
                [self.task_parameters['path']] + task_args,
                check=True,
                capture_output=True,
                text=True,
            )

            self.logger.info("Output:\n%s", result.stdout, extra={'tag': self.task_name})

            if result.returncode != 0:
                raise subprocess.CalledProcessError(returncode=result.returncode, cmd=result.args, output=result.stdout)

        except Exception as e:
            self.logger.error("Task failed with error: %s", e, extra={'tag': self.task_name})
            # Handle the exception or re-raise if necessary
            raise


class DummyTask(Task):
    def __init__(self, task_name, task_parameters, logger: logging.Logger):
        self.task_name = task_name
        self.task_parameters = task_parameters
        self.logger = logger

    def execute(self):
        message = self.task_parameters.get('message', 'No message provided')
        self.logger.info("%s: %s", message, self.task_name, extra={'tag': self.task_name})


class DummyRandomTask(Task):
    def __init__(self, task_name, task_parameters, logger: logging.Logger):
        self.task_name = task_name
        self.task_parameters = task_parameters
        self.logger = logger

    def execute(self):
        time_interval = self.task_parameters.get('time-seconds', [1, 5])
        sleep_time = random.uniform(time_interval[0], time_interval[1])

        message = self.task_parameters.get('message', 'No message provided')
        self.logger.info("%s: %s (Sleeping for %.2f seconds)", message, self.task_name, sleep_time, extra={'tag': self.task_name})

        time.sleep(sleep_time)

