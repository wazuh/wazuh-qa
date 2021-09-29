import subprocess

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


LOGGER = Logging.get_logger(QACTL_LOGGER)


def run_local_command(command):
    """Run local commands without getting the output, but validating the result code.

    Args:
        command (string): Command to run.
    """
    run = subprocess.Popen(command, shell=True)

    # Wait for the process to finish
    run.communicate()

    result_code = run.returncode

    if result_code != 0:
        raise QAValueError(f"The command {command} returned {result_code} as result code.", LOGGER.error,
                           QACTL_LOGGER)


def run_local_command_with_output(command):
    """Run local commands getting the command output.
    Args:
        command (string): Command to run.

    Returns:
        str: Command output
    """
    run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

    return run.stdout.read().decode()


def download_local_wazuh_qa_repository(branch, path):
    """Download wazuh QA repository in local machine.

    Args:
        branch (string): Wazuh QA repository branch.
        path (string): Local path where save the repository files.
    """
    command = f"git clone https://github.com/wazuh/wazuh-qa --branch {branch} --single-branch {path}"
    run_local_command_with_output(command)
