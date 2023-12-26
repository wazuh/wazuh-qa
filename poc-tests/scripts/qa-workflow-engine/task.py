# task.py
from abc import ABC, abstractmethod
from typing import Optional
import subprocess
import logging


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
        try:
            result = subprocess.run(
                [self.task_parameters['path']] + self.task_parameters['args'],
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
