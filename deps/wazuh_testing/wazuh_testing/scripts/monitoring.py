import csv
import signal
import sys
import json
import os
import time
import logging
import subprocess

from wazuh_testing.api import make_api_call, API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT, get_api_details_dict
from wazuh_testing.tools.performance.binary import Monitor

logger = logging.getLogger(__name__)
metrics_monitoring_pid = None

# TODO
# - Metrics copy from wazuh-metrics. It is better to change this by launching directly the wazuh-metrics script and handle the signals
# - Include the analysisd daemon
# - Include parametrization to the script
# - Testing in real environment


def signal_handler(sig, frame):
    global metrics_monitoring_pid

    print("Signal received. Exiting...")

    if metrics_monitoring_pid:
        os.kill(metrics_monitoring_pid, signal.SIGKILL)

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

    process = subprocess.Popen('wazuh-metrics', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    metrics_monitoring_pid = process.pid

    collect_data()

