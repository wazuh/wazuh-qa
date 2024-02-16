import csv
import signal
import sys
import json
import os
import time
import logging
import subprocess
import argparse
import threading

from wazuh_testing.api import make_api_call, API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT, get_api_details_dict
from wazuh_testing.tools.performance.binary import Monitor

logger = logging.getLogger(__name__)
metrics_monitoring_pid = None

STOP_STATISTICS_MONITORING = False

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


def create_csv_header(process, directory):
    file_path = os.path.join(directory, f'{process}.csv')

    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        if process == "wazuh-db":
            writer.writerow(["timestamp", "name", "queries_received", "queries_global", "queries_wazuhdb",
                             "time_execution", "time_global", "time_wazuhdb"])
        elif process == "wazuh-remoted":
            writer.writerow(["timestamp", "name", "bytes_received", "bytes_sent", "keys_reload_count",
                             "received_keepalive",
                             "received_request", "received_shutdown", "received_startup", "received_discarded",
                             "received_event", "sent_ack", "sent_ar", "sent_discarded", "sent_request", "sent_sca",
                             "sent_shared", "queue_size", "queue_usage"])
        elif process == "wazuh-analysisd":
            writer.writerow(["timestamp", "name", "bytes_received", "processed_events", "processed_events_received",
                             "decoded_agent", "syscheck", "dropped_agent", "dropped_syscheck", "writte_breakdown_alerts",
                             "queue_size_alerts", "queue_usage_alerts", "queue_syscheck_size", "queue_syscheck_usage"])


def parse_and_write_to_csv(data, process, directory):
    real_data = data['data']['affected_items']
    process_metrics = None
    for affected_item in real_data:
        if affected_item['name'] == process:
            process_metrics = affected_item
            break
    if not process_metrics:
        raise Exception(f"Process {process} not found in the data")

    row = []

    timestamp = process_metrics['timestamp']
    name = process_metrics['name']
    metrics = process_metrics['metrics']

    if process == "wazuh-db":
        queries_received = metrics['queries']['received']
        queries_global = metrics['queries']['received_breakdown']['global']
        queries_wazuhdb = metrics['queries']['received_breakdown']['wazuhdb']

        # Time
        time_execution = metrics['time']['execution']
        time_global = metrics['time']['execution_breakdown']['global']
        time_wazuhdb = metrics['time']['execution_breakdown']['wazuhdb']

        row = [timestamp, name, queries_received, queries_global, queries_wazuhdb, time_execution,
               time_global, time_wazuhdb]

    if process == "wazuh-remoted":
        bytes_received = metrics['bytes']['received']
        bytes_sent = metrics['bytes']['sent']
        keys_reload_count = metrics['keys_reload_count']

        received_keepalive = metrics['messages']['received_breakdown']['control_breakdown']['keepalive']
        received_request = metrics['messages']['received_breakdown']['control_breakdown']['request']
        received_shutdown = metrics['messages']['received_breakdown']['control_breakdown']['shutdown']
        received_startup = metrics['messages']['received_breakdown']['control_breakdown']['startup']
        received_discarded = metrics['messages']['received_breakdown']['discarded']
        received_event = metrics['messages']['received_breakdown']['event']

        sent_ack = metrics['messages']['sent_breakdown']['ack']
        sent_ar = metrics['messages']['sent_breakdown']['ar']
        sent_discarded = metrics['messages']['sent_breakdown']['discarded']
        sent_request = metrics['messages']['sent_breakdown']['request']
        sent_sca = metrics['messages']['sent_breakdown']['sca']
        sent_shared = metrics['messages']['sent_breakdown']['shared']

        queue_size = metrics['queues']['received']['size']
        queue_usage = metrics['queues']['received']['usage']

        row = [timestamp, name, bytes_received, bytes_sent, keys_reload_count, received_keepalive, received_request,
               received_shutdown, received_startup, received_discarded, received_event, sent_ack,
               sent_ar, sent_discarded, sent_request, sent_sca, sent_shared, queue_size, queue_usage]

    if process == "wazuh-analysisd":
        bytes_received = metrics['bytes']['received']
        processed_events = metrics['events']['processed']
        processed_events_received = metrics['events']['received']
        decoded_agent = metrics['events']['received_breakdown']['decoded_breakdown']['agent']

        syscheck = metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['syscheck']

        dropped_agent = metrics['events']['received_breakdown']['dropped_breakdown']['agent']
        dropped_syscheck = metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['syscheck']

        writte_breakdown_alerts = metrics['events']['written_breakdown']['alerts']
        queue_size_alerts = metrics['queues']['alerts']['size']
        queue_usage_alerts = metrics['queues']['alerts']['usage']

        queue_syscheck_size = metrics['queues']['syscheck']['size']
        queue_syscheck_usage = metrics['queues']['syscheck']['usage']

        row = [timestamp, name, bytes_received, processed_events, processed_events_received, decoded_agent, syscheck,
               dropped_agent, dropped_syscheck, writte_breakdown_alerts, queue_size_alerts, queue_usage_alerts, queue_syscheck_size, queue_syscheck_usage]

    file_path = os.path.join(directory, f'{process}.csv')

    with open(file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        if row:
            writer.writerow(row)
        else:
            writer.writerow([timestamp, name, "No data"])


def get_daemons_stats():
    host = "localhost"
    endpoint = "/manager/daemons/stats?daemons_list=wazuh-db,wazuh-analysisd,wazuh-remoted"
    api_details = get_api_details_dict(host=host)
    response = make_api_call(manager_address=host, endpoint=endpoint, headers=api_details['auth_headers'])

    if not response:
        raise Exception("Failed to retrieve data from API")
    else:
        return json.loads(response.content)

def collect_data(options, monitoring_evidences_directory):
    global STOP_STATISTICS_MONITORING

    for process in options.process_list:
        create_csv_header(process, monitoring_evidences_directory)

    while not STOP_STATISTICS_MONITORING:
        try:
            stats = get_daemons_stats()
            for process in options.process_list:
                parse_and_write_to_csv(stats, process, monitoring_evidences_directory)
        except Exception as e:
            print(f"Error occurred: {str(e)}")

        time.sleep(options.sleep_time)


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Wazuh monitoring script",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--time', dest='monitoring_time', type=float, required=True, action='store',
                        help='Type the time in that script will be running.')
    parser.add_argument('-o', '--output', dest='output_file', required=False, type=str, action='store',
                        default=None, help='Type the output file name.')
    parser.add_argument('-s', '--sleep', dest='sleep_time', type=float, default=1, action='store',
                        help='Type the time in seconds between each entry.')
    parser.add_argument('-p', '--processes', dest='process_list', required=False, type=str, nargs='+', action='store',
                        default=["wazuh-db", "wazuh-remoted", "wazuh-analysisd"],
                        help='Type the processes name to monitor separated by whitespace.')
    parser.add_argument('-u', '--units', dest='data_unit', default='KB', choices=['B', 'KB', 'MB'],
                        help='Type unit for the bytes-related values. Default bytes.')
    parser.add_argument('-v', '--version', dest='version', required=True, help='Version of the binaries. Default none.')

    return parser.parse_args()


if __name__ == "__main__":
    options = get_script_arguments()

    monitoring_start_time = time.strftime("%Y%m%d-%H%M%S")
    wazuh_version = options.version

    monitoring_evidences_directory = os.path.join(wazuh_version, monitoring_start_time)

    if options.output_file:
        monitoring_evidences_directory = options.output_file

    if not os.path.exists(monitoring_evidences_directory):
        os.makedirs(monitoring_start_time)

    signal.signal(signal.SIGINT, signal_handler)

    metrics_monitoring_process = subprocess.Popen(f"wazuh-metrics -p {options.process_list}",
                                                  shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    metrics_monitoring_pid = metrics_monitoring_process.pid
    statistics_monitoring_thread = threading.Thread(target=collect_data, args=(options, monitoring_evidences_directory,))
    statistics_monitoring_thread.start()

    time.sleep(options.monitoring_time)

    # Stop statistics monitoring
    STOP_STATISTICS_MONITORING = True

    # Stop metrics monitoring
    os.kill(metrics_monitoring_pid, signal.SIGKILL)
