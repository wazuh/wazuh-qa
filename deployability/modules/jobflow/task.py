# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import subprocess
import random
import time

from abc import ABC, abstractmethod
from jobflow.logger.logger import logger

class Task(ABC):
    """Abstract base class for tasks."""

    @abstractmethod
    def execute(self) -> None:
        """Execute the task."""
        pass

class ProcessTask(Task):
    """Task for executing a process."""

    def __init__(self, task_name: str, task_parameters: dict):
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

        task_args = []
        if self.task_parameters.get('args') is None:
            raise ValueError(f'Not argument found in {self.task_name}')

        for arg in self.task_parameters['args']:
            if isinstance(arg, str):
                task_args.append(arg)
            elif isinstance(arg, dict):
                key, value = list(arg.items())[0]
                if isinstance(value, list):
                    task_args.extend([f"--{key}={argvalue}" for argvalue in value])
                else:
                    task_args.append(f"--{key}={value}")
            else:
                logger.error(f'Could not parse arguments {arg}')

        logger.debug(f'Running task "{self.task_name}" with arguments: {task_args}')

        result = None
        try:
            result = subprocess.run(
                [self.task_parameters['path']] + task_args,
                check=True,
                capture_output=True,
                text=True,
            )
            logger.debug(f'Finished task "{self.task_name}" execution with result:\n{str(result.stdout)}')

            if result.returncode != 0:
                raise subprocess.CalledProcessError(returncode=result.returncode, cmd=result.args, output=result.stdout)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr
            if "KeyboardInterrupt" in error_msg:
                raise KeyboardInterrupt(f"Error executing process task with keyboard interrupt.")
            raise Exception(f"Error executing process task {e.stderr}")

class DummyTask(Task):
    def __init__(self, task_name, task_parameters):
        self.task_name = task_name
        self.task_parameters = task_parameters

    def execute(self):
        message = self.task_parameters.get('message', 'No message provided')
        logger.info("%s: %s", message, self.task_name, extra={'tag': self.task_name})

class DummyRandomTask(Task):
    def __init__(self, task_name, task_parameters):
        self.task_name = task_name
        self.task_parameters = task_parameters

    def execute(self):
        time_interval = self.task_parameters.get('time-seconds', [1, 5])
        sleep_time = random.uniform(time_interval[0], time_interval[1])

        message = self.task_parameters.get('message', 'No message provided')
        logger.info("%s: %s (Sleeping for %.2f seconds)", message, self.task_name, sleep_time, extra={'tag': self.task_name})

        time.sleep(sleep_time)

TASKS_HANDLERS = {
    'process': ProcessTask,
    'dummy': DummyTask,
    'dummy-random': DummyRandomTask,
}
