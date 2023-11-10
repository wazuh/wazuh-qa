import subprocess

from constants import WAZUH_CONTROL


def get_service() -> str:
    """
    Retrieves the name of the Wazuh service running on the current platform.

    Returns:
        str: The name of the Wazuh service.

    """
    control_output = subprocess.check_output([WAZUH_CONTROL, "info", "-t"], stderr=subprocess.PIPE)
    return control_output.decode('utf-8').strip()


def get_daemons_status() -> dict:
    """
    Get the status of the Wazuh daemons.
    
    Return: 
        dict: The daemons (keys) and their status(values).
    """
    daemons_status = {}

    control_output = subprocess.run([WAZUH_CONTROL, "status"], stdout=subprocess.PIPE)
    control_output_decoded = control_output.stdout.decode('utf-8')

    for line in control_output_decoded.split('\n'):
        if "running" in line:
            daemon_name = line.split(' ')[0]
            status = line.replace(daemon_name, '').replace('.', '').lstrip()
            daemons_status[daemon_name] = status

    return daemons_status
