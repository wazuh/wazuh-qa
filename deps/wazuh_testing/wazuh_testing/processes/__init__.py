import subprocess

from wazuh_testing.tools.services import check_if_process_is_running
from wazuh_testing import logger


def check_if_modulesd_is_running():
    """Check if modulesd daemon is running"""
    assert check_if_process_is_running('wazuh-modulesd'), 'wazuh-modulesd is not running. It may have crashed'


def check_if_daemons_are_running(daemons):
    """Check if daemons are running"""
    for daemon in daemons:
        assert check_if_process_is_running(daemon), f"{daemon} is not running. It may have crashed"


def execute_shell_command(command):
    try:
        output_shell = subprocess.run(command, shell=True, check=True, stderr=subprocess.PIPE)
        return output_shell
    except subprocess.CalledProcessError as exc:
        logger.error(f"Process failed because did not return a successful return code. "
                     f"Returned {exc.returncode}\n{exc}")
