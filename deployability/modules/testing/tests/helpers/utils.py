import chardet
import json
import psutil
import socket
import subprocess
import time

from pathlib import Path

from .constants import AGENTD_STATE, CLIENT_KEYS, WAZUH_CONTROL, AGENT_CONTROL


def run_command(binary: str, args: list = None) -> None:
    """
    Run a Wazuh binary with the given arguments.

    Args:
        binary (str): The binary to run.
        args (list): The arguments to pass to the binary.

    Returns:
        str: The output of the binary execution.
    """
    if not args:
        args = []

    output = subprocess.run([binary] + args, stdout=subprocess.PIPE)

    return output.stdout.decode('utf-8')


def get_service() -> str:
    """
    Retrieves the name of the Wazuh service running on the current platform.

    Returns:
        str: The name of the Wazuh service.

    """

    return run_command(WAZUH_CONTROL, ["info", "-t"]).strip()


def get_version() -> str:
    """
    Retrieves the version of the Wazuh installation on the current platform.

    Returns:
        str: The version of Wazuh installed.

    """

    return run_command(WAZUH_CONTROL, ["info", "-v"]).strip()


def get_revision() -> str:
    """
    Retrieves the version of the Wazuh installation on the current platform.

    Returns:
        str: The version of Wazuh installed.

    """

    return run_command(WAZUH_CONTROL, ["info", "-r"]).strip()


def get_service_status() -> str:
    """
    Get the status of the Wazuh service.

    Returns:
        str: The status of the Wazuh service.
    """
    if get_service() == "agent":
        service_name = "wazuh-agent"
    else:
        service_name = "wazuh-manager"

    return run_command("systemctl", ["is-active", service_name]).strip()


def get_daemons_status() -> dict:
    """
    Get the status of the Wazuh daemons.

    Return: 
        dict: The daemons (keys) and their status(values).
    """
    daemons_status = {}

    control_output = run_command(WAZUH_CONTROL, ["status"])

    for line in control_output.split('\n'):
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

    control_output = run_command(AGENT_CONTROL, ["-l"])

    for line in control_output.split('\n'):
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


def get_agent_connection_status(agent_id: str = None, timeout: int = 60) -> str:
    """
    Get the connection status of an agent.

    Args:
        agent_id (str, optional): The ID of the agent. Defaults to None.
        timeout (int, optional): Timeout in seconds for waiting on pending status. Defaults to 60 seconds.

    Raises:
        ValueError: If the service is "server" and no agent_id is provided.
        ValueError: If the agent is not found.

    Returns:
        str: The connection status of the agent.
    """
    if get_service() == "server" and not agent_id:
        raise ValueError("Agent id is required for server service.")

    if get_service() == "server":
        agent = [a for a in get_registered_agents() if a.get('ID') == agent_id]

        if not agent:

            raise ValueError("Agent not found.")

        status = agent[0].get('Status')
    else:
        start_time = time.time()
        
        while True:
            agentd_output = subprocess.run(
                ["sudo", "grep", "^status", AGENTD_STATE], stdout=subprocess.PIPE)

            agentd_output_decoded = agentd_output.stdout.decode('utf-8')

            status = agentd_output_decoded.split('=')[1].replace("'", "").strip()

            if status != 'pending' or (time.time() - start_time) >= timeout:
                break
            time.sleep(5)

        if status == 'pending':
            raise TimeoutError("Timeout reached while waiting for pending status.")

    return status


def get_file_encoding(file_path: str) -> str:
    """Detect and return the file encoding.

    Args:
        file_path (str): File path to check.

    Returns:
        encoding (str): File encoding.
    """
    with open(file_path, 'rb') as f:
        data = f.read()
        if len(data) == 0:
            return 'utf-8'
        result = chardet.detect(data)

    return result['encoding']


def file_monitor(monitored_file: str, target_string: str, timeout: int = 30) -> None:
    """
    Monitor a file for a specific string.

    Args:
        monitored_file (str): The file to monitor.
        target_string (str): The string to look for in the file.
        timeout (int, optional): The time to wait for the string to appear in the file. Defaults to 30.

    Returns:
        None: Returns None if the string is not found within the timeout.
        str: Returns the line containing the target string if found within the timeout.
    """
    encoding = get_file_encoding(monitored_file)

    # Check in the current file content for the string.
    with open(monitored_file, encoding=encoding) as _file:
        for line in _file:
            if target_string in line:

                return line

    # Start count to set the timeout.
    start_time = time.time()

    # Start the file monitoring for future lines.
    with open(monitored_file, encoding=encoding) as _file:
        # Go to the end of the file.
        _file.seek(0, 2)
        while time.time() - start_time < timeout:
            current_position = _file.tell()
            line = _file.readline()

            if not line:
                # No new line, wait for nex try.
                _file.seek(current_position)
                time.sleep(0.1)
            else:
                # New line, check if the string matches.
                if target_string in line:

                    return line


def check_agent_is_connected(agent_id: str, timeout: int = 60) -> bool:
    """
    Wait for an agent to connect to the manager, returns true when it does.

    Args:
        agent_id (str): The ID of the agent to wait for.

    Returns:
        bool: True if the agent connects within the timeout, False otherwise.
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        status = get_agent_connection_status(agent_id)
        if status in ["connected", "Active"]:

            return True
        time.sleep(1)

    raise False


def read_json_file(filepath: str | Path) -> dict:
    """
    Read a JSON file and return a dictionary.

    Args:
        filepath (str, Path): Path to the JSON file.

    Returns:
        dict: Dictionary with the JSON file content.
    """
    with open(filepath) as f_json:

        return json.load(f_json)


def get_client_keys() -> list[dict]:
    """
    Get the client keys from the client.keys file.

    Returns:
        list: List of dictionaries with the client keys.
    """
    clients = []
    with open(CLIENT_KEYS, 'r') as file:
        lines = file.readlines()
        for line in lines:
            _id, name, address, password = line.strip().split()
            client_info = {
                "id": _id,
                "name": name,
                "address": address,
                "password": password
            }
            clients.append(client_info)

    return clients


def is_port_in_use(port: int) -> bool:
    """
    Check if a port is in use.

    Args:
        port (int): The port to check.

    Returns:
        bool: True if the port is in use, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 80))
    sock.close()

    return True if result == 0 else False


def is_process_alive(process_name: str) -> bool:
    """
    Check if a process is running.

    Args:
        process_name (str): The name of the process to check.

    Returns:
        bool: True if the process is running, False otherwise.
    """

    return process_name in (p.name() for p in psutil.process_iter())


def dynamic_wait(expected_condition_func, cycles=10, waiting_time=10) -> None:
    """
    Waits the process during assigned cycles for the assigned seconds

    Args:
        expected_condition_func (function): The function that returns True when the expected condition is met
        cycles(int): Number of cycles
        waiting_Time(int): Number of seconds per cycle

    """
    for _ in range(cycles):
        if expected_condition_func():
            break
        else:
            time.sleep(waiting_time)
    else:
        raise RuntimeError(f'Time out')