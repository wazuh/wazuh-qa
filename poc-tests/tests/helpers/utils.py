import subprocess

from .constants import WAZUH_CONTROL, AGENT_CONTROL


def get_service() -> str:
    """
    Retrieves the name of the Wazuh service running on the current platform.

    Returns:
        str: The name of the Wazuh service.

    """
    control_output = subprocess.check_output(
        [WAZUH_CONTROL, "info", "-t"], stderr=subprocess.PIPE)
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


def get_registered_agents():
    """
    Get the registered agents on the manager.

    return:
        list: The registered agents.
    """
    registered_agents = []

    control_output = subprocess.run([AGENT_CONTROL, "-l"], stdout=subprocess.PIPE)
    control_output_decoded = control_output.stdout.decode('utf-8')

    for line in control_output_decoded.split('\n'):
        if "ID:" in line:
            agent_info = line.split(',')
            agent_dict = {
                'ID': agent_info[0].split(':')[1].strip(),
                'Name': agent_info[1].split(':')[1].strip(),
                'IP': agent_info[2].split(':')[1].strip(),
                'Status': agent_info[3].strip()
            }
            registered_agents.append(agent_dict)

    return registered_agents


def find_string_in_file(file_path: str, target: str) -> bool:
    """
    Reads a file and checks if the expected line is there.

    Args:
        file_path (str): The path of the file to read.
        target (str): The expected string.
        
    Returns:
        bool: True if the line is found, False otherwise.
    """
    with open(file_path, 'r') as file:
        for line in file:
            if target in line:
                return True
    return False
