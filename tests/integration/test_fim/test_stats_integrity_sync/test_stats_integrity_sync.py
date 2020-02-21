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
from multiprocessing import Process, Manager
from random import randrange
from shutil import rmtree
from struct import pack, unpack

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
        'mem': re.match(regex_mem, head).group(1),
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
        'cpu': str(current_stats['cpu'] - old_stats['cpu']),
        'mem': str(current_stats['mem']),
        'rchar': str(current_stats['rchar'] - old_stats['rchar']),
        'wchar': str(current_stats['wchar'] - old_stats['wchar']),
        'syscr': str(current_stats['syscr'] - old_stats['syscr']),
        'syscw': str(current_stats['syscw'] - old_stats['syscw']),
        'read_bytes': str(current_stats['read_bytes'] - old_stats['read_bytes']),
        'write_bytes': str(current_stats['write_bytes'] - old_stats['write_bytes']),
        'cancelled_write_bytes': str(current_stats['cancelled_write_bytes'] - old_stats['cancelled_write_bytes'])
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
        return int(re.match(regex, response).group(1))
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
        return int(re.match(regex, response).group(1))
    except AttributeError:
        raise AttributeError(f'[ERROR] Bad response (n_completions) from wazuh-db: {response}')


def get_agents(client_keys='/var/ossec/etc/client.keys'):
    """These function extract all agent ids in the client.keys file. It will not extract the ids that are removed (!)

    Create an external dict (no shared by the processes) and an internal dict (shared by the processes), every process
    has the external dict (agent_ids), that reference the internal and shared structure. This way, every process can
    check the status of the agents.

    Parameters
    ----------
    client_keys : str
        Path of the client.keys file.

    Returns
    -------
    dict
        Dictionary shared by all processes.
    """
    agent_regex = r'([0-9]+) [^!.+]+ .+ .+'
    agent_dict = dict()
    agent_ids = list()
    with open(client_keys, 'r') as keys:
        for line in keys.readlines():
            try:
                agent_ids.append(re.match(agent_regex, line).group(1))
            except AttributeError:
                pass

    for agent_id in agent_ids:
        agent_dict[agent_id.zfill(3)] = Manager().dict({
            'start': 0.0
        })

    return agent_dict


def replace_conf(eps, directory, buffer):
    """Function that sets up the configuration for the current test.
    Parameters
    ----------
    eps : str
        Events per second.
    directory : str
        Directory to be monitored.
    buffer : str
        Can be yes or no, <disabled>yes|no</disabled>.
    """
    new_config = str()
    directory_regex = r'.*<directories check_all=\"yes\">[\n\t ]*(.+)[\n\t ]*</directories>'
    eps_regex = r'.*<max_eps>[\n\t ]*([0-9]+)[\n\t ]*</max_eps>'
    buffer_regex = r'<client_buffer>[\n\t ]*<disabled>[\n\t ]*(yes|no)[\n\t ]*</disabled>[\n\t ]*</client_buffer>'

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'template_agent.conf'), 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = re.sub(directory_regex, '<directories check_all="yes">' + directory + '</directories>', line)
            line = re.sub(eps_regex, '<max_eps>' + eps + '</max_eps>', line)
            line = re.sub(buffer_regex, '<client_buffer><disabled>' + buffer + '</disabled></client_buffer>', line)
            new_config += line

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


def agent_checker(case, agent_id, agents_dict, filename, attempts_info, database_params, configuration):
    """Check that the current agent is restarted. When it has been restarted, marks the start time of the agent.
    If n_completions of the agent_id is greater than 0, the info_collector must be called.

    Parameters
    ----------
    case : int
        Case number.
    agent_id : str
        Agent id.
    agents_dict : dict of multi processes shared dict
        Dictionary with the start time of every agent.
    filename : str
        Path of the agent's info file.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    database_params : dict
        Database params to be applied for the current test.
    configuration : str
        Test configuration
    """
    if case == Cases.case0.value:
        alerts = open(ALERT_FILE_PATH, 'w')
        alerts.close()

        # Detect that the agent are been restarted
        def callback_detect_agent_restart(line):
            try:
                return re.match(rf'.*\"agent\":{{\"id\":\"({agent_id})\".*', line).group(1)
            except (IndexError, AttributeError):
                pass

        FileMonitor(ALERT_FILE_PATH).start(timeout=max_time_for_agent_setup,
                                           callback=callback_detect_agent_restart).result()

    modify_database(agent_id, **database_params)

    while True:
        actual_n_attempts = n_attempts(agent_id)
        actual_n_completions = n_completions(agent_id)
        if not agents_dict[agent_id]['start'] and actual_n_attempts > 0:
            agents_dict[agent_id]['start'] = time.time()
            attempts_info['start'] = True
            logger.info(f'Agent {agent_id} started at {agents_dict[agent_id]["start"]}')

        if agents_dict[agent_id]['start'] and (actual_n_attempts > max_n_attempts or actual_n_completions > 0):
            state = 'complete' if actual_n_attempts < max_n_attempts else 'except_max_attempts'
            info_collector(agents_dict[agent_id], agent_id, filename, attempts_info, configuration, actual_n_attempts,
                           actual_n_completions, state=state)
            break
        time.sleep(setup_environment_time)


def info_collector(agent, agent_id, filename, attempts_info, configuration, actual_n_attempts,
                   actual_n_completions, state='complete'):
    """Write the stats of the agent during the test.

    This stats will be written when the agent finish its test process (n_completions(agent_id) > 0).

    Parameters
    ----------
    agent : dict
        Individual dictionary with the start time of an agent.
    agent_id : str
        Agent id.
    filename : str
        Path of the agent's info file.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    state : str
        complete of except_max_attempts: Indicates if the agent took less attempts than the defined limits or not.
    configuration : str
        Test configuration
    """
    try:
        agent_df = pd.read_csv(filename)
    except FileNotFoundError:
        agent_df = pd.DataFrame(columns=["configuration", "agent_id", "n_attempts", "n_completions", "start_time",
                                         "end_time", "total_time", "state"])
    if state != 'complete':
        attempts_info['except_max_attempts'] = True
        attempts_info['agents_failed'] += 1
    logger.info(
        f"Info {agent_id} writing: "
        f"{agent_id},{actual_n_attempts},{actual_n_completions},{agent['start']},"
        f"{time.time()},{time.time() - agent['start']},{state}")
    agent_df.loc[len(agent_df)] = [configuration, agent_id, actual_n_attempts, actual_n_completions,
                                   agent['start'], time.time(), time.time() - agent['start'], state]
    agent_df.to_csv(filename, index=False)


def state_collector(case, agents_dict, configuration, stats_dir, attempts_info):
    """Get the stats of the .state files in the WAZUH_PATH/var/run folder.
    We can define the stats to get from each daemon in the daemons_dict.

    Parameters
    ----------
    case : int
        Case number.
    agents_dict : dict of shared dict
        Dictionary with the start time of every agent.
    configuration : str
        Test configuration
    stats_dir : str
        Stats folder.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.
    """

    def get_csv(daemon_df='ossec-analysisd'):
        filename_df = os.path.join(os.path.join(stats_dir, f"state-{daemon_df}.csv"))
        try:
            return pd.read_csv(filename_df)
        except FileNotFoundError:
            if daemon_df == 'ossec-analysisd':
                return pd.DataFrame(columns=['configuration', 'seconds', 'syscheck_events_decoded', 'syscheck_edps',
                                             'dbsync_queue_usage', 'dbsync_messages_dispatched', 'dbsync_mdps',
                                             'events_received', 'events_dropped', 'syscheck_queue_usage',
                                             'event_queue_usage'])
            elif daemon_df == 'ossec-remoted':
                return pd.DataFrame(columns=['configuration', 'seconds', 'queue_size', 'tcp_sessions', 'evt_count',
                                             'discarded_count', 'recv_bytes'])
            else:
                raise NameError(f'Invalid daemon detected: {daemon_df}')

    daemons_dict = {
        'ossec-analysisd': get_csv('ossec-analysisd'),
        'ossec-remoted': get_csv('ossec-remoted')
    }

    states_exists = False
    while not attempts_info['finish'] and attempts_info['agents_failed'] < len(agents_dict.keys()):
        for file in os.listdir(state_path):
            if file.endswith('.state'):
                states_exists = True
                daemon = str(file.split(".")[0])
                with open(os.path.join(state_path, file), 'r') as state_file:
                    file_content = state_file.read()
                values = [configuration, str(time.time())]
                # Skip configuration and seconds columns
                for field in list(daemons_dict[daemon])[2:]:
                    values.append(re.search(rf"{field}='([0-9.]+)'", file_content, re.MULTILINE).group(1))

                logger.debug(f'State {daemon} writing: {",".join(values)}')
                daemons_dict[daemon].loc[len(daemons_dict[daemon])] = values
        time.sleep(state_collector_time)

    if states_exists:
        for daemon, df in daemons_dict.items():
            filename = os.path.join(os.path.join(stats_dir, f"state-{daemon}.csv"))
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
    try:
        stats_df = pd.read_csv(filename)
    except FileNotFoundError:
        stats_df = pd.DataFrame(columns=['configuration', 'seconds', *list(get_stats(daemon).keys())])
    while not attempts_info['finish'] and attempts_info['agents_failed'] < len(agents_dict.keys()):
        diff = calculate_stats(old_stats, stats)
        old_stats = deepcopy(stats)
        logger.debug(f'Stats {daemon} writing: {time.time()},{",".join(diff.values())}')
        stats_df.loc[len(stats_df)] = [configuration, time.time(), *list(diff.values())]
        time.sleep(setup_environment_time)
        stats = get_stats(daemon)

    if attempts_info['agents_failed'] >= len(agents_dict.keys()):
        logger.info(f'Configuration finished. All agents reached the max_n_attempts, '
                    f'currently set up to {max_n_attempts}')

    # Avoid empty stats file in 0 files case
    if not diff:
        diff = calculate_stats(old_stats, stats)
        logger.info(f'Finishing stats {daemon} writing: {time.time()},{",".join(diff.values())}')
        stats_df.loc[len(stats_df)] = [configuration, time.time(), *list(diff.values())]

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
@pytest.mark.parametrize('eps, files, directory, buffer', [
    ('200', '0', '/test0k', 'no'),
    ('200', '5000', '/test5k', 'no'),
    ('5000', '5000', '/test5k', 'no'),
    ('200', '50000', '/test50k', 'no'),
    ('5000', '50000', '/test50k', 'yes'),
    ('200', '1000000', '/test1M', 'yes'),
    ('5000', '1000000', '/test1M', 'yes'),
    ('1000000', '1000000', '/test1M', 'yes'),
])
def test_initialize_stats_collector(eps, files, directory, buffer, case, modify_file, modify_all, restore_all,
                                    initial_clean, modify_local_internal_options):
    """Execute and launch all the necessary processes to check all the cases with all the specified configurations."""
    agents_dict = get_agents()
    attempts_info = Manager().dict({
        'start': False,
        'finish': False,
        'except_max_attempts': False,
        'agents_failed': 0
    })
    agents_checker, stats_checker = list(), list()
    database_params = {
        'modify_file': modify_file,
        'modify_all': modify_all,
        'restore_all': restore_all,
        'directory': directory,
        'total_files': files,
        'prefix': 'file_'
    }
    protocol = protocol_detection()
    configuration = f'case{case}_{protocol}_{eps}_eps_{files}files_client-buffer-' \
                    f'{"enabled" if buffer == "no" else "disabled"}'

    # If we are in case 1 or in case 2 and the number of files is 0, we will not execute the test since we cannot
    # modify the checksums because they do not exist
    if not (case == 1 and files == '0') and not (case == 2 and files == '0'):
        logger.info(f'Setting up the environment for for case{case}_{protocol}-{eps}eps-{files}files')
        truncate_file(ALERT_FILE_PATH)
        # Only modify the configuration if case 0 is executing
        if case == Cases.case0.value:
            replace_conf(eps, directory, buffer)

        # Launch one process for agent due to FileMonitor restriction (block the execution)
        for agent_id in agents_dict.keys():
            filename = os.path.join(stats_dir, f"info.csv")
            agents_checker.append(Process(target=agent_checker, args=(case, agent_id, agents_dict, filename,
                                                                      attempts_info, database_params, configuration,)))
            agents_checker[-1].start()

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
        logger.info(f'Started test for case{case}_{protocol}-{eps}eps-{files}files')
        state_collector_check = Process(target=state_collector, args=(case, agents_dict, configuration, stats_dir,
                                                                      attempts_info,))
        state_collector_check.start()
        for daemon in tested_daemons:
            filename = os.path.join(os.path.join(stats_dir, f"stats-{daemon}.csv"))
            stats_checker.append(Process(target=stats_collector, args=(filename, daemon, agents_dict, attempts_info,
                                                                       configuration,)))
            stats_checker[-1].start()
        while True:
            if check_all_n_completions(agents_dict.keys()) > 0:
                attempts_info['finish'] = True
            if not any([writer_.is_alive() for writer_ in stats_checker]) and \
                    not any([check_agent.is_alive() for check_agent in agents_checker]) and \
                    not state_collector_check.is_alive():
                logger.info('All processes are finished')
                break
            time.sleep(setup_environment_time)
    clean_environment()
