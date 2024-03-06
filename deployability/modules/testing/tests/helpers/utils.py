import json
import time
import chardet
import subprocess

from .constants import AGENTD_STATE, WAZUH_CONTROL, AGENT_CONTROL


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


def get_agent_connection_status(agent_id: str = None) -> str:
    """
    Get the connection status of an agent.

    Args:
        agent_id (str, optional): The ID of the agent. Defaults to None.

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
        agentd_output = subprocess.run(
            ["sudo", "grep", "^status", AGENTD_STATE], stdout=subprocess.PIPE)
        agentd_output_decoded = agentd_output.stdout.decode('utf-8')
        status = agentd_output_decoded.split('=')[1].replace("'", "").strip()

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


def read_json_file(filepath):
    with open(filepath) as f_json:
        return json.load(f_json)
