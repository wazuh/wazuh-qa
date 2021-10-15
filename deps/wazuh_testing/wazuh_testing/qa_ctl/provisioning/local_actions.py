import subprocess
import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError


LOGGER = Logging.get_logger(QACTL_LOGGER)


def run_local_command(command):
    """Run local commands without getting the output, but validating the result code.

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


def run_local_command_with_output(command):
    """Run local commands getting the command output.
    Args:
        command (string): Command to run.

    Returns:
        str: Command output
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
    wazuh_qa_path = os.path.join(path, 'wazuh-qa')

    mute_output = '&> /dev/null' if sys.platform != 'win32' else '>nul 2>&1'

    if os.path.exists(wazuh_qa_path):
        LOGGER.info(f"Pulling remote repository changes in {wazuh_qa_path} local repository")
        run_local_command_with_output(f"cd {wazuh_qa_path} && git pull {mute_output} && "
                                      f"git checkout {branch} {mute_output}")
    else:
        LOGGER.info(f"Downloading wazuh-qa repository in {wazuh_qa_path}")
        run_local_command_with_output(f"cd {path} && git clone https://github.com/wazuh/wazuh-qa {mute_output} && "
                                      f"cd {wazuh_qa_path} && git checkout {branch} {mute_output}")


def qa_ctl_docker_run(config_file, qa_branch, debug_level, topic):
    """Run qa-ctl in a Linux docker container. Useful when running qa-ctl in native Windows host.

    Args:
        config_file (str): qa-ctl configuration file name to run.
        qa_branch (str): Wazuh qa branch with which qa-ctl will be launched.
        debug_level (int): qa-ctl debug level.
        topic (str): Reason for running the qa-ctl docker.
    """
    debug_args = '' if debug_level == 0 else ('-d' if debug_level == 1 else '-dd')
    docker_args = f"{qa_branch} {config_file} --no-validation-logging {debug_args}"
    docker_image_name = 'wazuh/qa-ctl'
    docker_image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'deployment',
                                     'dockerfiles', 'qa_ctl')

    LOGGER.info(f"Building docker image for {topic}")
    run_local_command_with_output(f"cd {docker_image_path} && docker build -q -t {docker_image_name} .")

    LOGGER.info(f"Running the Linux container for {topic}")
    run_local_command(f"docker run --rm -v {os.path.join(gettempdir(), 'qa_ctl')}:/qa_ctl {docker_image_name} {docker_args}")
