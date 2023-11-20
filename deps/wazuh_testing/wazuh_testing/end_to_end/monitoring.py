import os
import tempfile
import re
from time import sleep

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.file import create_temp_file
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.end_to_end.regex import get_event_regex
from multiprocessing.pool import ThreadPool


def monitoring_events_host_monitoring(host_manager, monitoring_data):
    monitoring_file_content = ''
    results = {}

    for host, data in monitoring_data.items():
        monitoring_file_content += f"{host}:\n"
        for monitoring_event in data:
            string_limiter = "'" if '"' in monitoring_event.get("regex", "") else '"'
            monitoring_file_content += f'  - regex: {string_limiter}{monitoring_event.get("regex", "")}{string_limiter}\n'
            monitoring_file_content += f'    file: {string_limiter}{monitoring_event.get("file", "")}{string_limiter}\n'
            monitoring_file_content += f'    timeout: {monitoring_event.get("timeout", 0)}\n'

            temp_file = create_temp_file(monitoring_file_content)

            temporal_directory = tempfile.TemporaryDirectory()

            HostMonitor(inventory_path=host_manager.get_inventory_path(),
                        messages_path=temp_file,
                        tmp_path=temporal_directory.name).run()

    return results


def monitoring_events_multihost(host_manager, monitoring_data):
    def monitoring_event(host_manager, host, monitoring_elements):
        """
        Monitor the specified elements on a host.

        Parameters:
        - host_manager: An object managing hosts.
        - host: The target host.
        - monitoring_elements: A list of dictionaries containing regex, timeout, and file.

        Returns:
        - The first match found in the file content.

        Raises:
        - TimeoutError if no match is found within the specified timeout.
        """
        for element in monitoring_elements:
            regex, timeout, monitoring_file = element['regex'], element['timeout'], element['file']
            current_timeout = 0
            regex_match = None
            while current_timeout < timeout:
                # Get file content
                print(timeout)
                file_content = host_manager.get_file_content(host, monitoring_file)
                regex_match = re.search(regex, file_content)
                if regex_match:
                    break

                sleep(5)
                current_timeout += 5

            if not regex_match:
                raise TimeoutError("No match found within the specified timeout.")

    with ThreadPool() as pool:
        # Use the pool to map the function to the list of hosts
        pool.starmap(monitoring_event, [(host_manager, host, data) for host, data in monitoring_data.items()])


def generate_monitoring_logs_all_agent(host_manager, regex_list, timeout_list):
    monitoring_data = {}
    for agent in host_manager.get_group_hosts('agent'):
        monitoring_data[agent] = []
        for index, regex_index in enumerate(regex_list):
            os_name = host_manager.get_host_variables(agent)['os_name']
            monitoring_data[agent].append({
                'regex': regex_index,
                'file': logs_filepath_os[os_name],
                'timeout': timeout_list[index]

            })
    return monitoring_data


def generate_monitoring_logs_manager(host_manager, manager, regex, timeout):
    monitoring_data = {}
    os_name = host_manager.get_host_variables(manager)['os_name']
    monitoring_data[manager] = [{
        'regex': regex,
        'file': logs_filepath_os[os_name],
        'timeout': timeout

    }]

    return monitoring_data


def generate_monitoring_alerts_all_agent(host_manager, events_metadata):
    monitoring_data = {}

    for agent in host_manager.get_group_hosts('agent'):
        host_os_name = host_manager.get_host_variables(agent)['os'].split('_')[0]
        metadata_agent = events_metadata[host_os_name]

        if not host_manager.get_host_variables(agent)['manager'] in monitoring_data:
            monitoring_data[host_manager.get_host_variables(agent)['manager']] = []

        for event in metadata_agent[agent.get_host_variables(agent)['arch']]:
            event['parameters']['HOST_NAME'] = agent
            monitoring_element = {
                'regex': get_event_regex(event),
                'file': '/var/ossec/logs/alerts/alerts.json',
                'timeout': 120,
            }
            if 'parameters' in metadata_agent:
                monitoring_element['parameters'] = metadata_agent['parameters']

            monitoring_data[host_manager.get_host_variables(agent)['manager']].append(monitoring_element)