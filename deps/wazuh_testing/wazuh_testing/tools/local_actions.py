'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import subprocess
import sys

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError

LOGGER = Logging.get_logger(QACTL_LOGGER)


def run_local_command_printing_output(command):
    """Run local commands printing the output in the stdout. In addition, it is validate the result code.
    Args:
        command (string): Command to run.
    Raises:
        QAValueError: If the run command has failed (rc != 0).
    """
    if sys.platform == 'win32':
        run = subprocess.Popen(command, shell=True)
    else:
        run = subprocess.Popen(['/bin/bash', '-c', command])

    # Wait for the process to finish
    run.communicate()

    result_code = run.returncode

    if result_code != 0:
        raise QAValueError(f"The command {command} returned {result_code} as result code.", LOGGER.error,
                           QACTL_LOGGER)


def run_local_command_returning_output(command):
    """Run local commands catching and returning the stdout in a variable. Nothing is displayed on the stdout.
    Args:
        command (string): Command to run.
    Returns:
        str: Command output.
    """
    if sys.platform == 'win32':
        run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    else:
        run = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE)

    return run.stdout.read().decode()
