import subprocess
import sys

from wazuh_testing.tools.services import check_if_process_is_running


def check_if_modulesd_is_running():
    """Check if modulesd daemon is running"""
    assert check_if_process_is_running('wazuh-modulesd'), 'wazuh-modulesd is not running. It may have crashed'


def check_if_daemons_are_running(daemons):
    """Check if the specified daemons are running.

    Args:
        daemons (list(str)): Daemon names

    Returns:
        boolean, list(str): True if running, False otherwise. If false, it returns the daemons list that are not
                            running.
    """
    stopped_daemons = []

    for daemon in daemons:
        if not check_if_process_is_running(daemon):
            stopped_daemons.append(daemon)

    if len(stopped_daemons) > 0:
        return False, stopped_daemons

    return True, []


def run_local_command_printing_output(command):
    """Run local commands printing the output in the stdout. In addition, it is validate the result code.

    Args:
        command (string): Command to run.

    Raises:
        ValueError: If the run command has failed (rc != 0).
    """
    if sys.platform == 'win32':
        run = subprocess.Popen(command, shell=True)
    else:
        run = subprocess.Popen(['/bin/bash', '-c', command])

    # Wait for the process to finish
    run.communicate()

    result_code = run.returncode

    if result_code != 0:
        raise ValueError(f"The command {command} returned {result_code} as result code.")


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
