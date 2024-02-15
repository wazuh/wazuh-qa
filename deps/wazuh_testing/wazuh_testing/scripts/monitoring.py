import csv
import signal
import sys
import json
import os
import time
import logging

from wazuh_testing.api import make_api_call, API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT, get_api_details_dict
from wazuh_testing.tools.performance.binary import Monitor

logger = logging.getLogger(__name__)

# TODO
# - Metrics copy from wazuh-metrics. It is better to change this by launching directly the wazuh-metrics script and handle the signals
# - Include the analysisd daemon
# - Include parametrization to the script
# - Testing in real environment


def check_monitors_health():
    """Write the collected data in a CSV file.

    Args:
        options (argparse.Options): object containing the script options.

    Returns:
        bool: True if there were any errors. False otherwise.
    """
    healthy = True
    for process, monitors in ACTIVE_MONITORS.items():
        # Check if there is any unhealthy monitor
        if any(filter(lambda m: m.event.is_set(), monitors)):
            logger.warning(f'Monitoring of {process} failed. Attempting to create new monitor instances')

            try:
                # Try to get new PIDs
                process_pids = Monitor.get_process_pids(process)
                # Shutdown all the related monitors to the failed process (necessary for multiprocessing)
                for monitor in monitors:
                    monitor.shutdown()
            except ValueError:
                healthy = False
                logger.warning(f'Could not create new monitor instances for {process}')
                continue

            for i, pid in enumerate(process_pids):
                # Attempt to create new monitor instances for the process
                p_name = process if i == 0 else f'{process}_child_{i}'
                monitor = Monitor(process_name=p_name, pid=pid)
                monitor.start()

                try:
                    # Replace old monitors for new ones
                    ACTIVE_MONITORS[process][i] = monitor
                except IndexError:
                    ACTIVE_MONITORS[process].append(monitor)

    return healthy

def signal_handler(sig, frame):
    print("Signal received. Exiting...")
    sys.exit(0)


def create_csv_header():
    with open('data.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Name", "Queries Received", "Queries Global", "Time Execution", "Time Global", "Time WazuhDB"])


def parse_and_convert_to_csv(data):
    rows = []
    real_data = data['data']['affected_items'][0]

    timestamp = real_data['timestamp']
    name = real_data['name']
    metrics = real_data['metrics']

    queries_received = metrics['queries']['received']
    queries_global = metrics['queries']['received_breakdown']['global']
    queries_wazuhdb = metrics['queries']['received_breakdown']['wazuhdb']

    # Time
    time_execution = metrics['time']['execution']
    time_global = metrics['time']['execution_breakdown']['global']
    time_wazuhdb = metrics['time']['execution_breakdown']['wazuhdb']

    # ToDo: Include analisysd syscheck metrics

    rows.append([timestamp, name, queries_received, queries_global, time_execution, time_global, time_wazuhdb])

    with open('data.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)


def collect_data():
    if os.path.exists('data.csv'):
        os.remove('data.csv')

    create_csv_header()
    while True:
        try:
            host = "localhost"
            # TODO Include analyzisd daemon
            endpoint = f"/manager/daemons/stats?daemons_list=wazuh-db"
            api_details = get_api_details_dict(host='localhost')
            response = make_api_call(manager_address='localhost', endpoint=endpoint, headers=api_details['auth_headers'])

            if response.status_code == 200:
                parse_and_convert_to_csv(json.loads(response.content))
            else:
                print("Failed to retrieve data from API")

        except Exception as e:
            print(f"Error occurred: {str(e)}")
        time.sleep(5)


if __name__ == "__main__":

    ACTIVE_MONITORS = {}

    signal.signal(signal.SIGINT, signal_handler)

    process_list = ["wazuh-db"]

    # TODO: Include options for versioning dst_dir
    # TODO: Multithread to handle statistics and metrics

    # Replacae by call wazuh-metrics directly
    for process in process_list:
        # Launch a monitor for every possible child process
        for i, pid in enumerate(Monitor.get_process_pids(process)):
            p_name = process if i == 0 else f'{process}_child_{i}'
            monitor = Monitor(process_name=p_name, pid=pid, time_step=2,
                              version='v4.5.5', dst_dir='./testing')
            monitor.start()

            if process not in ACTIVE_MONITORS:
                ACTIVE_MONITORS[process] = []

            ACTIVE_MONITORS[process].append(monitor)

    collect_data()



