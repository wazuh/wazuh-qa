import logging

from wazuh_testing.tools.system import HostManager
from wazuh_testing.end_to_end.logs import truncate_remote_host_group_files


def clean_agents(host_manager: HostManager, restart_managers: bool = False) -> None:
    """Clean and register agents

    Args:
        host_manager (HostManager): An instance of the HostManager class.
        restart_managers (bool, optional): Whether to restart the managers. Defaults to False.
    """
    # Restart managers and stop agents
    logging.info("Stopping agents")
    host_manager.control_environment("stop", ["agent"], parallel=True)

    logging.info("Removing agents")
    host_manager.remove_agents()

    if restart_managers:
        logging.info("Restarting managers")
        host_manager.control_environment("restart", ["manager"], parallel=True)

    # Truncate alerts and logs of managers and agents
    logging.info("Truncate managers and agents logs")

    truncate_remote_host_group_files(host_manager, "all", "logs")
