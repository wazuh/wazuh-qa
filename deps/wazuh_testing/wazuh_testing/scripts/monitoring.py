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
import datetime

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit, stdin, stdout

from wazuh_testing.api import make_api_call, get_api_details_dict


metrics_monitoring_pid = None

STOP_STATISTICS_MONITORING = False

logger = logging.getLogger(__name__)


def get_database_fragmentation(options, monitoring_evidences_directory):

    # Create CSV header for framentation wazuhdb
    with open(os.path.join(monitoring_evidences_directory, "wazuhdb_fragmentation.csv"), 'w', newline='') as file:
        writer = csv.writer(file)
        row = ["timestamp"]
        for agent in options.agents:
            row.append(f"fragmentation_{agent}")

        writer.writerow(row)

    while not STOP_STATISTICS_MONITORING:
        timestamp = datetime.datetime.now()

        row = [timestamp]
        for agent in options.agents:
            query = f'agent {agent} get_fragmentation'

            last_vacuum_value = pretty(db_query(query))['fragmentation']

            row.append(last_vacuum_value)

        file_path = os.path.join(monitoring_evidences_directory, "wazuhdb_fragmentation.csv")

        with open(file_path, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(row)

        time.sleep(options.sleep_time)


def pretty(response):
    if response.startswith('ok '):
        try:
            data = json.loads(response[3:])
            return data
        except json.JSONDecodeError:
            return response[3:]
    else:
        return response


def db_query(query):
    WDB = '/var/ossec/queue/db/wdb'
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    query = query.encode()
    payload = pack("<I{0}s".format(len(query)), len(query), query)
    sock.send(payload)

    length = unpack("<I", sock.recv(4))[0]
    response = sock.recv(length)

    sock.close()

    return response.decode()


def setup_logger(log_file, debug=False):
    # Create a logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Create a file handler and set level to DEBUG
    logging_files = os.path.join(os.path.dirname(log_file), "monitoring_script_logging.log")
    file_handler = logging.FileHandler(logging_files)

    if debug:
        file_handler.setLevel(logging.DEBUG)
    else:
        file_handler.setLevel(logging.INFO)

    # Create a formatter and set it to the handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the file handler to the logger
    logger.addHandler(file_handler)

    return logger


def signal_handler(sig, frame):
    global metrics_monitoring_pid

    logger.info("Signal received. Exiting...")

    if metrics_monitoring_pid:
        os.kill(metrics_monitoring_pid, signal.SIGKILL)

    sys.exit(0)


def create_csv_header(process, directory):
    file_path = os.path.join(directory, f'{process}_stats.csv')

    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        if process == "wazuh-db":
            writer.writerow(["timestamp", "name", "DB Begin", "DB Close", "DB Commit", "DB Remove", "DB SQL", "DB Vacuum",
                             "DB Get Fragmentation", "Tables Syscheck FIM File", "Tables Syscheck FIM Registry",
                             "Tables Syscheck FIM Registry Key", "Tables Syscheck FIM Registry Value", "Tables Syscheck Syscheck",
                             "Global DB Backup", "DB SQL", "DB Vacuum", "DB Get Fragmentation", "Queries Received",
                             "Queries Global", "Queries WazuhDB", "Time Execution", "Time Global", "Time WazuhDB", "Time DB Open",
                             "Time DB Close", "Time DB Commit", "Time DB Remove", "Time DB SQL", "Time DB Vacuum", "Time DB Get Fragmentation",
                             "Time DB Begin", "Time Syscheck FIM File", "Time Syscheck FIM Registry", "Time Syscheck FIM Registry Key",
                             "Time Syscheck FIM Registry Value", "Time Syscheck Syscheck"])
        elif process == "wazuh-remoted":
            writer.writerow(["timestamp", "name", "bytes_received", "bytes_sent", "keys_reload_count",
                             "received_keepalive",
                             "received_request", "received_shutdown", "received_startup", "received_discarded",
                             "received_event", "sent_ack", "sent_ar", "sent_discarded", "sent_request", "sent_sca",
                             "sent_shared", "queue_size", "queue_usage"])
        elif process == "wazuh-analysisd":
            writer.writerow(["timestamp", "name", "bytes_received", "processed_events", "processed_events_received",
                             "decoded_agent", "decoded_events_syscheck", "dropped_agent", "dropped_syscheck",
                             "writte_breakdown_alerts", "queue_size_alerts", "queue_usage_alerts",
                             "queue_syscheck_size", "queue_syscheck_usage"])
        elif '.db' in process:
            writer.writerow(["timestamp", "name", "size"])



def parse_and_write_to_csv(data, process, directory):
    logger.debug(f"Processing data for process: {process}")

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

        # Tables Agent
        agent_db_begin = metrics['queries']['received_breakdown']['agent_breakdown']['db']['begin']
        agent_db_close = metrics['queries']['received_breakdown']['agent_breakdown']['db']['close']
        agent_db_commit = metrics['queries']['received_breakdown']['agent_breakdown']['db']['commit']
        agent_remove = metrics['queries']['received_breakdown']['agent_breakdown']['db']['remove']
        agent_sql = metrics['queries']['received_breakdown']['agent_breakdown']['db']['sql']
        agent_vacuum = metrics['queries']['received_breakdown']['agent_breakdown']['db']['vacuum']
        agent_get_fragmentation = metrics['queries']['received_breakdown']['agent_breakdown']['db']['get_fragmentation']

        # Tables Syscheck
        syscheck_fim_files = metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_file'] if 'fim_file' in metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        syscheck_fim_registry = metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry'] if 'fim_registry' in metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        syscheck_fim_registry_key = metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry_key'] if 'fim_registry_key' in metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        syscheck_fim_registry_value = metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry_value'] if 'fim_registry_value' in metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        syscheck_syscheck = metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['syscheck'] if 'syscheck' in metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck'] else 0

        # Global
        global_db_backup = metrics['queries']['received_breakdown']['global_breakdown']['db']['backup']
        global_db_sql = metrics['queries']['received_breakdown']['global_breakdown']['db']['sql']
        global_db_vacuum = metrics['queries']['received_breakdown']['global_breakdown']['db']['vacuum']
        global_db_get_fragmentation = metrics['queries']['received_breakdown']['global_breakdown']['db']['get_fragmentation']

        # Time
        time_execution = metrics['time']['execution']
        time_global = metrics['time']['execution_breakdown']['global']
        time_wazuhdb = metrics['time']['execution_breakdown']['wazuhdb']

        time_db_open = metrics['time']['execution_breakdown']['agent_breakdown']['db']['open'] if 'open' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_close = metrics['time']['execution_breakdown']['agent_breakdown']['db']['close'] if 'close' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_commit = metrics['time']['execution_breakdown']['agent_breakdown']['db']['commit'] if 'commit' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_remove = metrics['time']['execution_breakdown']['agent_breakdown']['db']['remove'] if 'remove' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_sql = metrics['time']['execution_breakdown']['agent_breakdown']['db']['sql'] if 'sql' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_vacuum = metrics['time']['execution_breakdown']['agent_breakdown']['db']['vacuum'] if 'vacuum' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_get_fragmentation = metrics['time']['execution_breakdown']['agent_breakdown']['db']['get_fragmentation'] if 'get_fragmentation' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0
        time_db_begin = metrics['time']['execution_breakdown']['agent_breakdown']['db']['begin'] if 'begin' in metrics['time']['execution_breakdown']['agent_breakdown']['db'] else 0

        time_syscheck_fim_files = metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_file'] if 'fim_file' in metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        time_syscheck_fim_registry = metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry'] if 'fim_registry' in metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        time_syscheck_fim_registry_key = metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry_key'] if 'fim_registry_key' in metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        time_syscheck_fim_registry_value = metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry_value'] if 'fim_registry_value' in metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck'] else 0
        time_syscheck_syscheck = metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['syscheck'] if 'syscheck' in metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck'] else 0

        row = [timestamp, name, agent_db_begin, agent_db_close, agent_db_commit, agent_remove, agent_sql, agent_vacuum,
               agent_get_fragmentation, syscheck_fim_files, syscheck_fim_registry, syscheck_fim_registry_key,
               syscheck_fim_registry_value, syscheck_syscheck, global_db_backup, global_db_sql, global_db_vacuum,
               global_db_get_fragmentation, queries_received, queries_global, queries_wazuhdb, time_execution,
               time_global, time_wazuhdb, time_db_open, time_db_close, time_db_commit, time_db_remove, time_db_sql,
               time_db_vacuum, time_db_get_fragmentation, time_db_begin, time_syscheck_fim_files, time_syscheck_fim_registry,
               time_syscheck_fim_registry_key, time_syscheck_fim_registry_value, time_syscheck_syscheck]

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
               dropped_agent, dropped_syscheck, writte_breakdown_alerts, queue_size_alerts, queue_usage_alerts,
               queue_syscheck_size, queue_syscheck_usage]

    file_path = os.path.join(directory, f'{process}_stats.csv')

    with open(file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        if row:
            writer.writerow(row)
        else:
            writer.writerow([timestamp, name, "No data"])


def get_daemons_stats(processes_list):
    host = "localhost"
    endpoint = f"/manager/daemons/stats?daemons_list={','.join(processes_list)}"

    api_details = get_api_details_dict(host=host)
    response = make_api_call(manager_address=host, endpoint=endpoint, headers=api_details['auth_headers'])

    if not response:
        logger.error(f"Error getting daemons stats: {response}")
    else:
        return json.loads(response.content)


def collect_data(options, monitoring_evidences_directory):
    global STOP_STATISTICS_MONITORING

    for process in options.process_list:
        create_csv_header(process, monitoring_evidences_directory)

    while not STOP_STATISTICS_MONITORING:
        try:
            stats = get_daemons_stats(options.process_list)
            with open(os.path.join(monitoring_evidences_directory, "daemons_full_stats.json"), 'a') as file:
                json.dump(stats, file)
                file.write("\n")

            for process in options.process_list:
                parse_and_write_to_csv(stats, process, monitoring_evidences_directory)
        except Exception as e:
            logger.error(f"Error collecting data: {e}")

        time.sleep(options.sleep_time)


def get_database_size(options, monitoring_evidences_directory):
    global STOP_STATISTICS_MONITORING

    for database in os.listdir('/var/ossec/queue/db'):
        if database.startswith("00") and database.endswith(".db"):
            create_csv_header(database, monitoring_evidences_directory)

    while not STOP_STATISTICS_MONITORING:
        for database in os.listdir('/var/ossec/queue/db'):
            if database.startswith("00") and database.endswith(".db"):
                file_stats = os.stat(os.path.join('/var/ossec/queue/db', database))
                size = file_stats.st_size  # Bytes
                timestamp = datetime.datetime.now()
                name = database
                row = [timestamp, name, size]

                file_path = os.path.join(monitoring_evidences_directory, f'{database}_stats.csv')

                with open(file_path, 'a', newline='') as file:
                    writer = csv.writer(file)
                    if row:
                        writer.writerow(row)
                    else:
                        writer.writerow([timestamp, name, "No data"])

        time.sleep(options.sleep_time)


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description="Wazuh monitoring script",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--time', dest='monitoring_time', type=float, required=True, action='store',
                        help='Type the time in that script will be running.')
    parser.add_argument('-o', '--output', dest='output_file', required=False, type=str, action='store',
                        default=None, help='Type the output file name.')
    parser.add_argument('-s', '--sleep', dest='sleep_time', type=float, default=5, action='store',
                        help='Type the time in seconds between each entry.')
    parser.add_argument('-p', '--processes', dest='process_list', required=False, type=str, nargs='+', action='store',
                        default=["wazuh-db", "wazuh-remoted", "wazuh-analysisd"],
                        help='Type the processes name to monitor separated by whitespace.')
    parser.add_argument('-u', '--units', dest='data_unit', default='KB', choices=['B', 'KB', 'MB'],
                        help='Type unit for the bytes-related values. Default bytes.')
    parser.add_argument('-v', '--version', dest='version', required=True, help='Version of the binaries. Default none.')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Enable debug mode.')

    parser.add_argument('-a', '--agents', dest='agents', required=False, type=str, nargs='+', action='store',
                        default=None, help='Type the agents id to monitor separated by whitespace.')

    return parser.parse_args()


def main(options):
    global STOP_STATISTICS_MONITORING

    monitoring_start_time = time.strftime("%Y%m%d-%H%M%S")
    wazuh_version = options.version

    monitoring_evidences_directory = os.path.join(wazuh_version, monitoring_start_time)

    if options.output_file:
        monitoring_evidences_directory = options.output_file

    if not os.path.exists(monitoring_evidences_directory):
        os.makedirs(monitoring_evidences_directory)

    global logger
    logger = setup_logger(os.path.join(monitoring_evidences_directory, "monitoring.log"), options.debug)

    signal.signal(signal.SIGINT, signal_handler)

    # Start metrics monitoring
    logger.info(f"Starting metrics monitoring for processes: {options.process_list}")
    metrics_monitoring_process = subprocess.Popen(f"wazuh-metrics -p {' '.join(options.process_list)} "
                                                  f"--store {monitoring_evidences_directory}",
                                                  shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    metrics_monitoring_pid = metrics_monitoring_process.pid

    logger.info(f"Starting statistics monitoring for processes: {options.process_list}")
    statistics_monitoring_thread = threading.Thread(target=collect_data,
                                                    args=(options, monitoring_evidences_directory,))
    statistics_monitoring_thread.start()

    logger.info("Starting database size monitoring")
    database_monitoring_thread = threading.Thread(target=get_database_size,
                                                  args=(options, monitoring_evidences_directory,))
    database_monitoring_thread.start()

    logger.info("Monitoring get fragmentation for wazuhdb")
    fragmentation_monitoring = threading.Thread(target=get_database_fragmentation, args=(options, monitoring_evidences_directory,))
    fragmentation_monitoring.start()


    logger.info(f"Monitoring started. Monitoring time: {options.monitoring_time} seconds. Please wait...")
    time.sleep(options.monitoring_time)

    # Stop statistics monitoring
    STOP_STATISTICS_MONITORING = True

    # Stop metrics monitoring
    os.kill(metrics_monitoring_pid, signal.SIGKILL)


if __name__ == "__main__":
    options = get_script_arguments()
    main(options)
