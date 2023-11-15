import os
import tempfile

from wazuh_testing.end_to_end import logs_filepath_os
from wazuh_testing.tools.file import create_temp_file
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.end_to_end.regex import get_event_regex


def monitoring_events(host_manager, monitoring_data):
    monitoring_file_content = ''
    results = {}

    for host, data in monitoring_data.items():
        monitoring_file_content += f"{host}:\n"
        for monitoring_event in data:
            string_limiter = "'" if '"' in monitoring_event.get("regex", "") else '"'
            print(f"String limiter {string_limiter}")
            monitoring_file_content += f'  - regex: {string_limiter}{monitoring_event.get("regex", "")}{string_limiter}\n'
            monitoring_file_content += f'    path: {string_limiter}{monitoring_event.get("path", "")}{string_limiter}\n'
            monitoring_file_content += f'    timeout: {monitoring_event.get("timeout", 0)}\n'

        temp_file = create_temp_file(monitoring_file_content)
        try:
            temporal_directory = tempfile.TemporaryDirectory()
            print(temporal_directory.name)
            results.update(HostMonitor(inventory_path=host_manager.get_inventory_path(), messages_path=temp_file, tmp_path=temporal_directory.name).run())
        except TimeoutError:
            pass

        os.remove(temp_file)

    return results


def generate_monitoring_logs_all_agent(host_manager, regex_list, timeout_list):
    monitoring_data = {}
    for agent in host_manager.get_group_hosts('agent'):
        monitoring_data[agent] = []
        for index, regex_index in enumerate(regex_list):
            os_name = host_manager.get_host_variables(agent)['os_name']
            monitoring_data[agent].append({
                'regex': regex_index,
                'path': logs_filepath_os[os_name],
                'timeout': timeout_list[index]

            })
    return monitoring_data


def generate_monitoring_logs_manager(host_manager, manager, regex, timeout):
    monitoring_data = {}
    os_name = host_manager.get_host_variables(manager)['os_name']
    monitoring_data[manager] = [{
        'regex': regex,
        'path': logs_filepath_os[os_name],
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
                'path': '/var/ossec/logs/alerts/alerts.json',
                'timeout': 120,
            }

            if 'parameters' in metadata_agent:
                monitoring_element['parameters'] = metadata_agent['parameters']

            monitoring_data[host_manager.get_host_variables(agent)['manager']].append(monitoring_element)