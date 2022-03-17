import subprocess
import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.github_checks import branch_exists
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.file import delete_path_recursively, recursive_directory_creation


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


def download_local_wazuh_qa_repository(branch, path):
    """Download wazuh QA repository in local machine.

    Important note: Path must not include the wazuh-qa folder

    Args:
        branch (string): Wazuh QA repository branch.
        path (string): Local path where save the repository files.
    """
    # Create path if it does not exist
    recursive_directory_creation(path)

    wazuh_qa_path = os.path.join(path, 'wazuh-qa')
    mute_output = '&> /dev/null' if sys.platform != 'win32' else '>nul 2>&1'
    command = ''

    if not branch_exists(branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{branch} branch does not exist in Wazuh QA repository.", LOGGER.error, QACTL_LOGGER)

    # Delete previous files if exist
    delete_path_recursively(wazuh_qa_path)

    if sys.platform == 'win32':
        command = f"cd {path} && curl -OL https://github.com/wazuh/wazuh-qa/archive/{branch}.tar.gz {mute_output} && " \
                  f"tar -xzf {branch}.tar.gz {mute_output} && move wazuh-qa-{branch} wazuh-qa {mute_output} && " \
                  f"del {branch}.tar.gz {mute_output}"
    else:
        command = f"cd {path} && curl -Ls https://github.com/wazuh/wazuh-qa/archive/{branch}.tar.gz | tar zx " \
                  f"{mute_output} && mv wazuh-* wazuh-qa {mute_output} && rm -rf *tar.gz {mute_output}"

    LOGGER.debug(f"Downloading {branch} files of wazuh-qa repository in {wazuh_qa_path}")

    run_local_command_returning_output(command)


def qa_ctl_docker_run(config_file, qa_branch, debug_level, topic):
    """Run qa-ctl in a Linux docker container. Useful when running qa-ctl in native Windows host.

    Args:
        config_file (str): qa-ctl configuration file name to run.
        qa_branch (str): Wazuh qa branch with which qa-ctl will be launched.
        debug_level (int): qa-ctl debug level.
        topic (str): Reason for running the qa-ctl docker.
    """
    debug_args = '' if debug_level == 0 else ('-d' if debug_level == 1 else '-dd')
    docker_args = f"{qa_branch} {config_file} --no-validation {debug_args}"

    docker_image_name = 'wazuh/qa-ctl'
    docker_image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'deployment',
                                     'dockerfiles', 'qa_ctl')

    LOGGER.info(f"Building docker image for {topic}")
    run_local_command_returning_output(f"cd {docker_image_path} && docker build -q -t {docker_image_name} .")

    LOGGER.info(f"Running the Linux container for {topic}")
    run_local_command_printing_output(f"docker run --rm -v {os.path.join(gettempdir(), 'wazuh_qa_ctl')}:/wazuh_qa_ctl "
                                      f"{docker_image_name} {docker_args}")
