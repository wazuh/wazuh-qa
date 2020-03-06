# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import socket
import subprocess
import time
from copy import deepcopy
from enum import Enum
from random import randrange
from shutil import rmtree
from struct import pack, unpack
from threading import Thread, Lock

import numpy as np
import pandas as pd
import pytest
from wazuh_testing import logger
from wazuh_testing.tools import WAZUH_PATH, WAZUH_CONF, ALERT_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=3)]

# variables

agent_conf = os.path.join(WAZUH_PATH, 'etc', 'shared', 'default', 'agent.conf')
state_path = os.path.join(WAZUH_PATH, 'var', 'run')
db_path = '/var/ossec/queue/db/wdb'
setup_environment_time = 1  # Seconds
state_collector_time = 1  # Seconds
max_time_for_agent_setup = 300  # Seconds
max_n_attempts = 50
tested_daemons = ["wazuh-db", "ossec-analysisd", "ossec-remoted"]
stats_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stats', 'metrics')
dataframe_write_every_rows = 10
state_configuration = {
    "analysisd.state_interval": state_collector_time,
    "remoted.state_interval": state_collector_time
}


class Cases(Enum):
    """
        Case 0: In this case, we start from an empty database.

        Case 1: Once the synchronization process is completed,
        a random checksum in the database will be changed.

        Case 2: Modifies all the checksums of the database entries.
    """
    case0 = 0
    case1 = 1
    case2 = 2


# Fixtures

@pytest.fixture(scope='module')
def initial_clean():
    """Clean the environment."""
    rmtree(stats_dir, ignore_errors=True)
    os.makedirs(stats_dir, exist_ok=True)


@pytest.fixture(scope='module')
def modify_local_internal_options():
    """Replace the local_internal_options file"""
    with open(os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf'), 'w') as f:
        for conf, value in state_configuration.items():
            f.write(f'{conf}={value}\n')


# Functions


def db_query(agent, query):
    """Run a query against wazuh_db for a specific agent.

    Parameters
    ----------
    agent : str
        Database identifier.
    query : str
        Query to be executed.

    Returns
    -------
    str
        Return the wazuh-db's socket response.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(db_path)

        msg = f'agent {agent} sql {query}'.encode()
        sock.sendall(pack(f"<I{len(msg)}s", len(msg), msg))

        length = unpack("<I", sock.recv(4, socket.MSG_WAITALL))[0]
        return sock.recv(length, socket.MSG_WAITALL).decode(errors='ignore')


def get_total_disk_info(daemon):
    """Get total disk read/write info from /proc/[pid]/io.

    Parameters
    ----------
    daemon : str
        Daemon for whom we will get the stats.

    Returns
    -------
    tuple of str
        Total read value and total write value
    """
    regex_rchar = r"rchar: ([0-9]+)"
    regex_wchar = r"wchar: ([0-9]+)"
    regex_syscr = r"syscr: ([0-9]+)"
    regex_syscw = r"syscw: ([0-9]+)"
    regex_read = r"read_bytes: ([0-9]+)"
    regex_write = r"write_bytes: ([0-9]+)"
    regex_cancelled_write_bytes = r"cancelled_write_bytes: ([0-9]+)"
    pid = subprocess.check_output(['pidof', daemon]).decode().strip()

    with open(os.path.join(f'/proc/{pid}/io'), 'r') as io_info:
        info = io_info.read()

    return {
        'rchar': float(re.search(regex_rchar, info).group(1)) / 1024,  # KB
        'wchar': float(re.search(regex_wchar, info).group(1)) / 1024,  # KB
        'syscr': float(re.search(regex_syscr, info).group(1)),  # IO/operations
        'syscw': float(re.search(regex_syscw, info).group(1)),  # IO/operations
        'read_bytes': float(re.search(regex_read, info).group(1)) / 1024,  # KB
        'write_bytes': float(re.search(regex_write, info).group(1)) / 1024,  # KB
        'cancelled_write_bytes': float(re.search(regex_cancelled_write_bytes, info).group(1)) / 1024  # KB
    }


def get_total_cpu_info(daemon):
    """Get the total CPU usage by the specified daemon.

    Parameters
    ----------
    daemon : str
        Daemon to be monitored.

    Returns
    -------
    int
        Total CPU usage at this moment.
    """
    pid = subprocess.check_output(['pidof', daemon]).decode().strip()
    cpu_file = "/proc/" + pid + "/stat"
    with open(cpu_file, 'r') as cpu_info:
        data = cpu_info.read().split()
        cpu_total = int(data[13]) + int(data[14])

    return cpu_total


def get_stats(daemon):
    """Get CPU, RAM, disk read and disk write stats using ps and pidstat.

    Parameters
    ----------
    daemon : str
        Daemon for whom we will get the stats.

    Returns
    -------
    list of str
        Return CPU, RAM, Disk reading, Disk writing, Total disk reading, total disk writing.
    """
    io_stats = get_total_disk_info(daemon)
    regex_mem = rf"{daemon} *([0-9]+)"
    ps = subprocess.Popen(["ps", "-axo", "comm,rss"], stdout=subprocess.PIPE)
    grep = subprocess.Popen(["grep", daemon], stdin=ps.stdout, stdout=subprocess.PIPE)
    head = subprocess.check_output(["head", "-n1"], stdin=grep.stdout).decode().strip()

    return {
        'cpu': get_total_cpu_info(daemon),
        'mem': np.int64(re.match(regex_mem, head).group(1)),
        'rchar': io_stats['rchar'],
        'wchar': io_stats['wchar'],
        'syscr': io_stats['syscr'],
        'syscw': io_stats['syscw'],
        'read_bytes': io_stats['read_bytes'],
        'write_bytes': io_stats['write_bytes'],
        'cancelled_write_bytes': io_stats['cancelled_write_bytes']
    }


def calculate_stats(old_stats, current_stats):
    """Get CPU, RAM, disk read and disk write stats using ps and pidstat.

    Parameters
    ----------
    old_stats : dict
        Dict with the previous daemon stats.
    current_stats : dict
        Dict with the current daemon stats.

    Returns
    -------
    list of str
        Return CPU, RAM, Disk reading, Disk writing, Total disk reading, total disk writing.
    """
    return {
        'cpu': float(current_stats['cpu'] - old_stats['cpu']),
        'mem': np.int64(current_stats['mem']),
        'rchar': float(current_stats['rchar'] - old_stats['rchar']),
        'wchar': float(current_stats['wchar'] - old_stats['wchar']),
        'syscr': float(current_stats['syscr'] - old_stats['syscr']),
        'syscw': float(current_stats['syscw'] - old_stats['syscw']),
        'read_bytes': float(current_stats['read_bytes'] - old_stats['read_bytes']),
        'write_bytes': float(current_stats['write_bytes'] - old_stats['write_bytes']),
        'cancelled_write_bytes': float(current_stats['cancelled_write_bytes'] - old_stats['cancelled_write_bytes'])
    }


def n_attempts(agent):
    """Return n_attempts in sync_info table.

    Parameters
    ----------
    agent : str
        Check the number of attempts for this agent.

    Returns
    -------
    int
        Return the number of attempts for the specified agent.
    """
    regex = r"ok \[{\"n_attempts\":([0-9]+)}\]"
    response = db_query(agent, 'SELECT n_attempts FROM sync_info')

    try:
        return np.int16(re.match(regex, response).group(1))
    except AttributeError:
        raise AttributeError(f'[ERROR] Bad response (n_attempts) from wazuh-db: {response}')


def n_completions(agent):
    """Return n_completions in sync_info table.

    Parameters
    ----------
    agent : str
        Check the number of completions for this agent.

    Returns
    -------
    int
        Return the number of completions for the specified agent.
    """
    regex = r"ok \[{\"n_completions\":([0-9]+)}\]"
    response = db_query(agent, 'SELECT n_completions FROM sync_info')

    try:
        return np.int16(re.match(regex, response).group(1))
    except AttributeError:
        raise AttributeError(f'[ERROR] Bad response (n_completions) from wazuh-db: {response}')


def get_files_with_checksum(agent, checksum, total_files=5000):
    """Get the number of files with the specified checksum in the agent database.

    Parameters
    ----------
    agent : str
        Agent id.
    checksum : str
        Specified checksum.
    total_files : int
        Total files of this test.

    Returns
    -------
    str
        Percentage of the remaining files with the custom checksum.
    """
    count_regex = r'ok \[{\"count\(file\)\":([0-9]+)\}\]'
    completions = db_query(agent, f'SELECT count(file) FROM fim_entry WHERE NOT checksum="{checksum}"')

    return str((int(re.search(count_regex, completions).group(1)) / total_files) * 100)


def get_agents():
    """These function extract all agent ids in the client.keys file. It will not extract the ids that are removed (!)
    or not active.

    Returns
    -------
    dict
        Agents information dict
    """
    agent_dict, agent_ids = dict(), list()
    agent_regex = r' +ID: ([0-9]{3}), .+ Active$'
    agents_status = subprocess.check_output([f"{WAZUH_PATH}/bin/agent_control", '-lc']).decode().strip()
    for line in agents_status.split('\n'):
        try:
            agent_ids.append(str(re.search(agent_regex, line).group(1)))
        except AttributeError:
            pass

    for agent_id in agent_ids:
        agent_dict[agent_id.lstrip('0')] = {
            'start': 0.0,
            'dataframe': None
        }

    return agent_dict


def replace_conf(sync_eps, fim_eps, directory, buffer):
    """Function that sets up the configuration for the current test.
    Parameters
    ----------
    sync_eps : str
        Events per second (synchronization)
    fim_eps : str
        Events per second (fim)
    directory : str
        Directory to be monitored.
    buffer : str
        Can be yes or no, <disabled>yes|no</disabled>.
    """
    directories_regex = r"<directories check_all=\"yes\">(TESTING_DIRECTORY)</directories>"
    fim_eps_regex = r"<max_eps>(FIM_EPS)</max_eps>"
    sync_eps_regex = r"<max_eps>(SYNC_EPS)</max_eps>"
    buffer_regex = r'<client_buffer><disabled>(CLIENT)</disabled></client_buffer>'
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'template_agent.conf'), 'r') as f:
        content = f.read()
        new_config = re.sub(re.search(directories_regex, content).group(1), directory, content)
        new_config = re.sub(re.search(sync_eps_regex, new_config).group(1), str(sync_eps), new_config)
        new_config = re.sub(re.search(fim_eps_regex, new_config).group(1), str(fim_eps), new_config)
        new_config = re.sub(re.search(buffer_regex, new_config).group(1), buffer, new_config)
        new_config += "<!-- {0}  -->".format(randrange(1000))
        with open(agent_conf, 'w') as conf:
            conf.write(new_config)

    # Set Read/Write permissions to agent.conf
    os.chmod(agent_conf, 0o666)


def check_all_n_completions(agents_list):
    """Return min value of n_completions between all agents.

    Parameters
    ----------
    agents_list : list
        List of agent ids.

    Returns
    -------
    int
        Minimum number of completions of the tested agents.
    """
    all_n_completions = list()
    for agent_id in list(agents_list):
        all_n_completions.append(n_completions(agent_id))

    return min(all_n_completions)


def modify_database(agent_id, directory, prefix, total_files, modify_file, modify_all, restore_all):
    """ Modify the database files

    Parameters
    ----------
    agent_id : str
        Database identifier.
    directory : str
        Directory of the file to which we will modify your checksum.
    prefix : str
        Prefix of the filename.
    total_files
        Total files in the directory.
    modify_file : bool
        Flag for modify the checksum of a file.
    modify_all
        Flag for modify all checksums in the database.
    restore_all
        Flag that indicate if all entries in the fim_entry table should be deleted.
    """
    checksum = None
    if modify_file:
        total_files = int(total_files)
        if total_files == 0:
            total_files = 1
        checksum = 'new_checksum'
        file = f"{directory}/{prefix}{randrange(total_files)}"
        db_query(agent_id, f'UPDATE fim_entry SET checksum="{checksum}" WHERE file="{file}"')
        logger.info(f'Modify checksum of {file}, set to {checksum}')
    if modify_all:
        checksum = 'new_checksum2'
        db_query(agent_id, f'UPDATE fim_entry SET checksum="{checksum}"')
        logger.info(f'Modify all checksums to {checksum}')
    if restore_all:
        db_query(agent_id, 'DELETE FROM fim_entry')

    db_query(agent_id, 'UPDATE sync_info SET n_attempts=0')
    db_query(agent_id, 'UPDATE sync_info SET n_completions=0')

    return checksum


def append_to_dataframe(filename, df):
    """This function append the dataframe to the filename (csv)

    Parameters
    ----------
    filename : str
        CSV filename.
    df : pandas.DataFrame
        Current dataframe

    Returns
    -------
    pandas.DataFrame
        Empty dataframe.
    """
    if os.path.exists(filename):
        df.to_csv(filename, mode='a', index=False, header=False)
    else:
        df.to_csv(filename, index=False)

    return df.iloc[0:0]


def agent_checker(case, agent_id, agents_dict, attempts_info, database_params, configuration, num_files):
    """Check that the current agent is restarted. When it has been restarted, marks the start time of the agent.
    If n_completions of the agent_id is greater than 0, the info_collector must be called.

    Parameters
    ----------
    case : int
        Case number.
    agent_id : str
        Agent id.
    agents_dict : dict
        Dictionary with the start time of every agent.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    database_params : dict
        Database params to be applied for the current test.
    configuration : str
        Test configuration
    num_files : str
        Number of files of this test
    """
    if case == Cases.case0.value:
        alerts = open(ALERT_FILE_PATH, 'w')
        alerts.close()

        # Detect that the agent are been restarted
        def callback_detect_agent_restart(line):
            try:
                return re.match(rf'.*\"agent\":{{\"id\":\"({agent_id.zfill(3)})\".*', line).group(1)
            except (IndexError, AttributeError):
                pass

        FileMonitor(ALERT_FILE_PATH).start(timeout=max_time_for_agent_setup,
                                           callback=callback_detect_agent_restart).result()

    checksum = modify_database(agent_id, **database_params)
    while True:
        actual_n_attempts = n_attempts(agent_id)
        actual_n_completions = n_completions(agent_id)
        if not agents_dict[agent_id]['start'] and actual_n_attempts > 0:
            lock = Lock()
            lock.acquire()
            agents_dict[agent_id]['start'] = np.float32(time.time())
            lock.release()
            attempts_info['start'] = True
            logger.info(f'Agent {agent_id} started at {agents_dict[agent_id]["start"]}')

        if agents_dict[agent_id]['start'] and (actual_n_attempts > max_n_attempts or actual_n_completions > 0):
            state = 'complete' if actual_n_attempts < max_n_attempts else 'except_max_attempts'
            info_collector(agents_dict, agent_id, attempts_info, configuration, actual_n_attempts,
                           actual_n_completions, state=state, checksum=checksum, num_files=num_files)
            break
        time.sleep(setup_environment_time)


def info_collector(agents_dict, agent_id, attempts_info, configuration, actual_n_attempts,
                   actual_n_completions, num_files, state='complete', checksum=None):
    """Write the stats of the agent during the test.

    This stats will be written when the agent finish its test process (n_completions(agent_id) > 0).

    Parameters
    ----------
    agents_dict : dict
        Dictionary with the start time of every agent.
    agent_id : str
        Agent id.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    num_files : str
        Number of files of this test
    state : str
        complete of except_max_attempts: Indicates if the agent took less attempts than the defined limits or not.
    configuration : str
        Test configuration
    checksum : str or None
        New checksum for files or None if there is no modifications
    """
    if state != 'complete':
        attempts_info['except_max_attempts'] = True
        attempts_info['agents_failed'] += 1
    if state != 'complete' and checksum:
        completion = get_files_with_checksum(agent_id, checksum, int(num_files))
    elif state != 'complete' and not checksum:
        completion = 'Case0: no checksums modified'
    else:
        completion = None
    logger.info(
        f"Info {agent_id} writing: "
        f"{agent_id},{actual_n_attempts},{actual_n_completions},{agents_dict[agent_id]['start']},"
        f"{time.time()},{time.time() - agents_dict[agent_id]['start']},{state},{completion}")
    end_time = np.float32(time.time())
    lock = Lock()
    lock.acquire()
    agents_dict[agent_id]['dataframe'] = {'configuration': configuration, 'agent_id': agent_id,
                                          'n_attempts': actual_n_attempts, 'n_completions': actual_n_completions,
                                          'start_time': agents_dict[agent_id]['start'], 'end_time': end_time,
                                          'total_time': np.float32(end_time - agents_dict[agent_id]['start']),
                                          'state': str(state), 'complete(%)': str(completion)}
    lock.release()


def finish_agent_info(agents_dict):
    """Write the agent info after all agents were complete.

    Parameters
    ----------
    agents_dict : dict
        Dictionary with the start time of every agent.
    """
    agent_filename = os.path.join(stats_dir, f"info.csv")
    columns = ["configuration", "agent_id", "n_attempts", "n_completions", "start_time", "end_time", "total_time",
               "state", "complete(%)"]
    merge_agent_df = pd.DataFrame(columns=columns)
    merge_agent_df = merge_agent_df.astype(dtype={'configuration': 'object', 'agent_id': 'object',
                                                  'n_attempts': 'int16', 'n_completions': 'int16',
                                                  'start_time': 'float32', 'end_time': 'float32',
                                                  'total_time': 'float32', 'state': 'object', 'complete(%)': 'object'})

    for agent in agents_dict.values():
        if agent['dataframe']:
            merge_agent_df = merge_agent_df.append([agent['dataframe']], ignore_index=True)
    merge_agent_df.to_csv(agent_filename, index=False, mode='a', header=False)


def state_collector(agents_dict, configuration, stats_path, attempts_info):
    """Get the stats of the .state files in the WAZUH_PATH/var/run folder.
    We can define the stats to get from each daemon in the daemons_dict.

    Parameters
    ----------
    agents_dict : dict of shared dict
        Dictionary with the start time of every agent.
    configuration : str
        Test configuration
    stats_path : str
        Stats folder.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    """

    def get_csv(daemon_df='ossec-analysisd'):
        filename = os.path.join(os.path.join(stats_path, f"state-{daemon_df}.csv"))
        if daemon_df == 'ossec-analysisd':
            state_df = pd.DataFrame(columns=['configuration', 'seconds', 'syscheck_events_decoded', 'syscheck_edps',
                                             'dbsync_queue_usage', 'dbsync_messages_dispatched', 'dbsync_mdps',
                                             'events_received', 'events_dropped', 'syscheck_queue_usage',
                                             'event_queue_usage'])
            state_df = state_df.astype(
                dtype={'configuration': 'object', 'seconds': 'float32', 'syscheck_events_decoded': 'float32',
                       'syscheck_edps': 'float32', 'dbsync_queue_usage': 'float32',
                       'dbsync_messages_dispatched': 'float32', 'dbsync_mdps': 'float32',
                       'events_received': 'float32', 'events_dropped': 'float32', 'syscheck_queue_usage': 'float32',
                       'event_queue_usage': 'float32'})
        elif daemon_df == 'ossec-remoted':
            state_df = pd.DataFrame(columns=['configuration', 'seconds', 'queue_size', 'tcp_sessions', 'evt_count',
                                             'discarded_count', 'recv_bytes'])
            state_df = state_df.astype(
                dtype={'configuration': 'object', 'seconds': 'float32', 'queue_size': 'float32',
                       'tcp_sessions': 'float32', 'evt_count': 'float32', 'discarded_count': 'float32',
                       'recv_bytes': 'float32'})
        else:
            raise NameError(f'Invalid daemon detected: {daemon_df}')

        return state_df

    daemons_dict = {
        'ossec-analysisd': get_csv('ossec-analysisd'),
        'ossec-remoted': get_csv('ossec-remoted')
    }

    states_exists = False
    counter = 0
    filename_analysisd = os.path.join(os.path.join(stats_path, "state-ossec-analysisd.csv"))
    filename_remoted = os.path.join(os.path.join(stats_path, "state-ossec-remoted.csv"))
    while not attempts_info['finish'] and attempts_info['agents_failed'] < len(agents_dict.keys()):
        for file in os.listdir(state_path):
            if file.endswith('.state'):
                states_exists = True
                daemon = str(file.split(".")[0])
                with open(os.path.join(state_path, file), 'r') as state_file:
                    file_content = state_file.read()
                values = {'configuration': str(configuration), 'seconds': time.time()}
                # Skip configuration and seconds columns
                for field in list(daemons_dict[daemon])[2:]:
                    values[f'{field}'] = np.float32(
                        re.search(rf"{field}='([0-9.]+)'", file_content, re.MULTILINE).group(1))

                logger.debug(f'State {daemon} writing: {",".join(map(str, values.values()))}')
                daemons_dict[daemon] = daemons_dict[daemon].append([values], ignore_index=True)
        counter += 1
        if counter % dataframe_write_every_rows == 0:
            logger.debug('Writing ossec-analysisd state chunk')
            logger.debug('Writing ossec-remoted state chunk')
            daemons_dict['ossec-analysisd'] = append_to_dataframe(filename_analysisd, daemons_dict['ossec-analysisd'])
            daemons_dict['ossec-remoted'] = append_to_dataframe(filename_remoted, daemons_dict['ossec-remoted'])
            counter = 0
        time.sleep(state_collector_time)

    if states_exists:
        for daemon, df in daemons_dict.items():
            filename = os.path.join(os.path.join(stats_path, f"state-{daemon}.csv"))
            df.to_csv(filename, index=False)
        logger.info(f'Finished state collector')


def stats_collector(filename, daemon, agents_dict, attempts_info, configuration):
    """Collect the stats of the current daemon until all agents have finished the integrity process.

    Parameters
    ----------
    filename : str
        Path of the stats file for the current daemon.
    daemon : str
        Daemon tested.
    agents_dict : dict of shared dict
        Dictionary with the start time of every agent.
    attempts_info : shared dict
        Dictionary with a flag that indicates the number of agents that exceed the limit of n_attempts.
    configuration : str
        Test configuration
    """
    stats = get_stats(daemon)
    old_stats = deepcopy(stats)
    diff = None
    stats_df = pd.DataFrame(columns=['configuration', 'seconds', *list(get_stats(daemon).keys())])
    stats_df = stats_df.astype(dtype={'configuration': 'object', 'seconds': 'float32', 'cpu': 'int8', 'mem': 'int32',
                                      'rchar': 'float32', 'wchar': 'float32', 'syscr': 'float32', 'syscw': 'float32',
                                      'read_bytes': 'float32', 'write_bytes': 'float32',
                                      'cancelled_write_bytes': 'float32'})

    counter = 0
    while not attempts_info['finish'] and attempts_info['agents_failed'] < len(agents_dict.keys()):
        diff = calculate_stats(old_stats, stats)
        old_stats = deepcopy(stats)
        logger.debug(f'Stats {daemon} writing: {time.time()},{",".join(map(str, diff.values()))}')
        stats_df = stats_df.append([{'configuration': configuration, 'seconds': time.time(), **diff}],
                                   ignore_index=True)
        time.sleep(setup_environment_time)
        stats = get_stats(daemon)
        counter += 1
        if counter % dataframe_write_every_rows == 0:
            logger.debug(f'Writing {daemon} stats chunk')
            stats_df = append_to_dataframe(filename, stats_df)
            counter = 0

    if attempts_info['agents_failed'] >= len(agents_dict.keys()):
        logger.info(f'Configuration finished. All agents reached the max_n_attempts, '
                    f'currently set up to {max_n_attempts}')

    # Avoid empty stats file in 0 files case
    if not diff:
        diff = calculate_stats(old_stats, stats)
        logger.info(f'Finishing stats {daemon} writing: {time.time()},{",".join(map(str, diff.values()))}')
        stats_df = stats_df.append([{'configuration': configuration, 'seconds': time.time(), **diff}],
                                   ignore_index=True)
    stats_df.to_csv(filename, index=False)


def protocol_detection(ossec_conf_path=WAZUH_CONF):
    """Detect the protocol configuration.

    Parameters
    ----------
    ossec_conf_path : str
        ossec.conf path.

    Returns
    -------
    str
        udp or tcp.
    """
    try:
        with open(ossec_conf_path) as ossec_conf:
            return re.search(r'<protocol>(udp|tcp)</protocol>', ossec_conf.read()).group(1)
    except AttributeError:
        raise AttributeError(f'[ERROR] No protocol detected in {ossec_conf_path}')


def clean_environment():
    """Remove the states files between tests."""
    for file in os.listdir(state_path):
        if file.endswith('.state'):
            os.unlink(os.path.join(state_path, file))


@pytest.mark.parametrize('case, modify_file, modify_all, restore_all', [
    (Cases.case0.value, False, False, True),
    (Cases.case1.value, True, False, False),
    (Cases.case2.value, False, True, False)
])
@pytest.mark.parametrize('sync_eps, fim_eps, files, directory, buffer', [
    ('200', '200', '0', '/test0k', 'no'),
    ('200', '200', '5000', '/test5k', 'no'),
    ('1000', '200', '5000', '/test5k', 'no'),
    ('5000', '200', '5000', '/test5k', 'yes'),
    ('200', '200', '10000', '/test10k', 'no'),
    ('1000', '200', '10000', '/test10k', 'no'),
    ('5000', '200', '10000', '/test10k', 'yes'),
    ('200', '200', '25000', '/test25k', 'no'),
    ('1000', '200', '25000', '/test25k', 'no'),
    ('5000', '200', '25000', '/test25k', 'yes'),
    ('200', '200', '50000', '/test50k', 'no'),
    ('1000', '200', '50000', '/test50k', 'no'),
    ('5000', '200', '50000', '/test50k', 'yes'),
    ('200', '200', '100000', '/test100k', 'no'),
    ('1000', '200', '100000', '/test100k', 'no'),
    ('5000', '200', '100000', '/test100k', 'yes'),
])
def test_initialize_stats_collector(fim_eps, sync_eps, files, directory, buffer, case, modify_file, modify_all,
                                    restore_all, initial_clean, modify_local_internal_options):
    """Execute and launch all the necessary threads to check all the cases with all the specified configurations."""
    agents_dict = get_agents()
    attempts_info = {
        'start': False,
        'finish': False,
        'except_max_attempts': False,
        'agents_failed': 0
    }
    database_params = {
        'modify_file': modify_file,
        'modify_all': modify_all,
        'restore_all': restore_all,
        'directory': directory,
        'total_files': files,
        'prefix': 'file_'
    }
    threads = list()
    protocol = protocol_detection()
    configuration = f'{str(len(agents_dict.keys()))}agents_case{case}_{protocol}_{sync_eps}' \
                    f'sync_eps_{fim_eps}fim_eps_{files}files_client-buffer-' \
                    f'{"enabled" if buffer == "no" else "disabled"}'

    # If we are in case 1 or in case 2 and the number of files is 0, we will not execute the test since we cannot
    # modify the checksums because they do not exist
    if not (case == 1 and files == '0') and not (case == 2 and files == '0'):
        logger.info(f'Setting up the environment for for case{case}_{protocol}-{sync_eps}sync_eps_{fim_eps}fim_eps-'
                    f'{files}files')
        truncate_file(ALERT_FILE_PATH)
        # Only modify the configuration if case 0 is executing
        if case == Cases.case0.value:
            replace_conf(sync_eps, fim_eps, directory, buffer)

        # Launch one thread for agent due to FileMonitor restriction (block the execution)
        for agent_id in agents_dict.keys():
            threads.append(Thread(target=agent_checker, args=(case, agent_id, agents_dict, attempts_info,
                                                              database_params, configuration, files),
                                  name=f'Agent{agent_id}_thread'))
            threads[-1].start()

        # Block the test until one agent starts
        seconds = 0
        while not attempts_info['start']:
            if seconds >= max_time_for_agent_setup:
                raise TimeoutError('[ERROR] The agents are not ready')
            if seconds == 0:
                logger.info(f'Waiting for agent attempt...')
            time.sleep(setup_environment_time)
            seconds += setup_environment_time

        # We started the stats collector as the agents are ready
        logger.info(f'Started test for case{case}_{protocol}-{sync_eps}sync_eps_{fim_eps}fim_eps-{files}files')
        threads.append(Thread(target=state_collector, args=(agents_dict, configuration, stats_dir, attempts_info,),
                              name='state_collector_thread'))
        threads[-1].start()
        for daemon in tested_daemons:
            filename = os.path.join(os.path.join(stats_dir, f"stats-{daemon}.csv"))
            threads.append(Thread(target=stats_collector, args=(filename, daemon, agents_dict, attempts_info,
                                                                configuration,),
                                  name=f'{daemon}_stats_thread'))
            threads[-1].start()
        while True:
            if check_all_n_completions(list(agents_dict.keys())) > 0:
                attempts_info['finish'] = True
            if not any([thread.is_alive() for thread in threads]):
                logger.info('All threads are finished')
                finish_agent_info(agents_dict)
                break
            time.sleep(setup_environment_time)

    for thread in threads:
        thread.join()
    clean_environment()
