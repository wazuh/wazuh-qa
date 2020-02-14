# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import time
from enum import Enum
from multiprocessing import Process, Manager
from random import randrange
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack

import pytest

from wazuh_testing.tools import WAZUH_PATH, WAZUH_CONF, ALERT_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=3)]

# variables

agent_conf = os.path.join(WAZUH_PATH, 'etc', 'shared', 'default', 'agent.conf')
state_path = os.path.join(WAZUH_PATH, 'var', 'run')
db_path = '/var/ossec/queue/db/wdb'
manager_ip = '172.19.0.100'
setup_environment_time = 1  # Seconds
state_collector_time = 5  # Seconds
max_time_for_agent_setup = 180  # Seconds
max_n_attempts = 20
tested_daemons = ["wazuh-db", "ossec-analysisd", "ossec-remoted"]


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
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(db_path)

    msg = f'agent {agent} sql {query}'.encode()
    sock.send(pack(f"<I{len(msg)}s", len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')


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
    pid = os.popen('pidof ' + daemon).read().strip()

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
    pid = os.popen('pidof ' + daemon).read().strip()
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

    return {
        'cpu': str(get_total_cpu_info(daemon)),
        'rchar': str(io_stats['rchar']),
        'wchar': str(io_stats['wchar']),
        'syscr': str(io_stats['syscr']),
        'syscw': str(io_stats['syscw']),
        'read_bytes': str(io_stats['read_bytes']),
        'write_bytes': str(io_stats['write_bytes']),
        'cancelled_write_bytes': str(io_stats['cancelled_write_bytes'])
    }


def calculate_stats(daemon, cpu=0, rchar=0, wchar=0, syscr=0, syscw=0, read_bytes=0, write_bytes=0,
                    cancelled_write_bytes=0):
    """Get CPU, RAM, disk read and disk write stats using ps and pidstat.

    Parameters
    ----------
    daemon : str
        Daemon for whom we will get the stats.
    cpu : str or float
        Previous CPU value.
    rchar : str or float
        Previous rchar value.
    wchar : str or float
        Previous wchar value.
    syscr : str or float
        Previous syscr value.
    syscw : str or float
        Previous syscw value.
    read_bytes : str or float
        Previous read_bytes value.
    write_bytes : str or float
        Previous write_bytes value.
    cancelled_write_bytes : str or float
        Previous cancelled_write_bytes value.

    Returns
    -------
    list of str
        Return CPU, RAM, Disk reading, Disk writing, Total disk reading, total disk writing.

    """
    regex_mem = r"ossec-syscheckd *([0-9]+)"
    ps = os.popen("ps -axo comm,rss | grep ossec-syscheckd | head -n1")
    io_stats = get_total_disk_info(daemon)

    return {
        'cpu': str(float(get_total_cpu_info(daemon)) - float(cpu)),
        'mem': re.match(regex_mem, ps.read()).group(1),
        'rchar': str(float(io_stats['rchar']) - float(rchar)),
        'wchar': str(float(io_stats['wchar']) - float(wchar)),
        'syscr': str(float(io_stats['syscr']) - float(syscr)),
        'syscw': str(float(io_stats['syscw']) - float(syscw)),
        'read_bytes': str(float(io_stats['read_bytes']) - float(read_bytes)),
        'write_bytes': str(float(io_stats['write_bytes']) - float(write_bytes)),
        'cancelled_write_bytes': str(float(io_stats['cancelled_write_bytes']) - float(cancelled_write_bytes))
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
    address_regex = r".*<address>([0-9.]+)</address>"
    directory_regex = r'.*<directories check_all=\"yes\">(.+)</directories>'
    eps_regex = r'.*<max_eps>([0-9]+)</max_eps>'
    buffer_regex = r'<client_buffer><disabled>(yes|no)</disabled></client_buffer>'

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/template_agent.conf'), 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = re.sub(address_regex, '<address>' + manager_ip + '</address>', line)
            line = re.sub(directory_regex, '<directories check_all="yes">' + directory + '</directories>', line)
            line = re.sub(eps_regex, '<max_eps>' + eps + '</max_eps>', line)
            line = re.sub(buffer_regex, '<client_buffer><disabled>' + buffer + '</disabled></client_buffer>', line)
            new_config += line

        with open(agent_conf, 'w') as conf:
            conf.write(new_config)
    # Set Read/Write permissions to agent.conf
    os.chmod(agent_conf, 0o666)


def check_all_n_attempts(agents_list):
    """Return max value of n_attempts between all agents.

    Parameters
    ----------
    agents_list : list
        List of agent ids.

    Returns
    -------
    int
        Maximum number of attempts of the tested agents.

    """
    all_n_attempts = list()
    for agent_id in list(agents_list):
        all_n_attempts.append(n_attempts(agent_id))

    return max(all_n_attempts)


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
        print(f'[DB] Modify checksum of {file}, set to {checksum}')
    if modify_all:
        checksum = 'new_checksum2'
        db_query(agent_id, f'UPDATE fim_entry SET checksum="{checksum}"')
        print(f'[DB] Modify all checksums to {checksum}')
    if restore_all:
        db_query(agent_id, 'DELETE FROM fim_entry')

    db_query(agent_id, 'UPDATE sync_info SET n_attempts=0')
    db_query(agent_id, 'UPDATE sync_info SET n_completions=0')

    while n_completions(agent_id) != 0 and n_attempts(agent_id) != 0:
        print('[INFO] Waiting for wazuh-db')
        time.sleep(0.1)


def agent_checker(case, agent_id, agents_dict, filename, attempts_info, database_params):
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
        if n_attempts(agent_id) > 0 and agents_dict[agent_id]['start'] == 0.0:
            if not attempts_info['start']:
                with open(filename, 'w') as info_agent:
                    info_agent.write("agent_id,n_attempts,n_completions,start_time,end_time,total_time,state\n")
            agents_dict[agent_id]['start'] = time.time()
            attempts_info['start'] = True
            print(f'[AGENT] Agent {agent_id} started at {agents_dict[agent_id]["start"]}')
        actual_n_attempts = n_attempts(agent_id)
        if (n_completions(agent_id) > 0 or actual_n_attempts > max_n_attempts) and \
                agents_dict[agent_id]['start'] != 0.0:
            state = 'complete' if actual_n_attempts < max_n_attempts else 'except_max_attempts'
            info_collector(agents_dict[agent_id], agent_id, filename, attempts_info, state=state)
            break


def info_collector(agent, agent_id, filename, attempts_info, state='complete'):
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

    """
    if state != 'complete':
        attempts_info['except_max_attempts'] = True
        attempts_info['agents_failed'] += 1
    with open(filename, 'a') as info_agent:
        print(
            f"[AGENT] Info {agent_id} writing: "
            f"{agent_id},{n_attempts(agent_id)},{n_completions(agent_id)},{agent['start']},"
            f"{time.time()},{time.time() - agent['start']},{state}")
        info_agent.write(f"{agent_id},{n_attempts(agent_id)},{n_completions(agent_id)},{agent['start']},"
                         f"{time.time()},{time.time() - agent['start']},{state}\n")


def state_collector(case, agents_dict, buffer, stats_dir, attempts_info):
    """Gets the stats of the .state files in the WAZUH_PATH/var/run folder.
    We can define the stats to get from each daemon in the daemons_dict.

    Parameters
    ----------
    case : int
        Case number.
    agents_dict : dict of shared dict
        Dictionary with the start time of every agent.
    buffer : str
        Set disabled to yes or no.
    stats_dir : str
        Stats folder.
    attempts_info : shared dict
        Dictionary with a flag that indicates if the stats collector must start.

    """
    daemons_dict = {
        'ossec-analysisd': {
            'headers': ['syscheck_events_decoded', 'syscheck_edps', 'dbsync_queue_usage',
                        'dbsync_messages_dispatched', 'dbsync_mdps', 'events_received', 'events_dropped',
                        'syscheck_queue_usage', 'event_queue_usage'],
            'deleted': False,
            'no_headers': True},
        'ossec-remoted': {
            'headers': ['queue_size', 'tcp_sessions', 'evt_count', 'discarded_count', 'recv_bytes'],
            'deleted': False,
            'no_headers': True
        }
    }

    while check_all_n_completions(agents_dict.keys()) == 0 and \
            attempts_info['agents_failed'] < len(agents_dict.keys()):
        for file in os.listdir(state_path):
            if file.endswith('.state'):
                daemon = str(file.split(".")[0])
                filename = os.path.join(os.path.join(stats_dir, f"state-{daemon}_case{case}_{buffer}.csv"))
                if not daemons_dict[daemon]['deleted']:
                    try:
                        os.unlink(filename)
                    except FileNotFoundError:
                        pass
                    daemons_dict[daemon]['deleted'] = True
                with open(filename, 'a') as state:
                    values = list()
                    file_content = open(os.path.join(state_path, file), 'r').read()
                    for field in daemons_dict[daemon]['headers']:
                        values.append(
                            re.search(rf"{field}='([0-9.]+)'", file_content, re.MULTILINE).group(1))
                    if daemons_dict[daemon]['no_headers']:
                        state.write(f"seconds,{','.join(daemons_dict[daemon]['headers'])}\n")
                        daemons_dict[daemon]['no_headers'] = False
                    # print(f'[STATE] State {daemon} writing: {time.time()},{",".join(values)}')
                    state.write(f"{time.time()},{','.join(values)}\n")
        time.sleep(state_collector_time)

    print(f'[STATE] Finished state collector')


def stats_collector(filename, daemon, agents_dict, attempts_info):
    """Collects the stats of the current daemon until all agents have finished the integrity process.

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

    """
    stats, old_stats = None, None
    with open(filename, 'w') as file_:
        file_.write(f"seconds,cpu,mem,{','.join(list(get_stats(daemon).keys())[1:])}\n")
        while check_all_n_completions(agents_dict.keys()) == 0 and \
                attempts_info['agents_failed'] < len(agents_dict.keys()):
            if check_all_n_attempts(agents_dict.keys()) > 0:
                if old_stats:
                    stats = calculate_stats(daemon, **old_stats)
                old_stats = get_stats(daemon)
                if stats:
                    # print(f'[STATS] Stats {daemon} writing: {time.time()},{",".join(stats.values())}')
                    file_.write(f'{time.time()},{",".join(stats.values())}\n')
            time.sleep(setup_environment_time)

    if attempts_info['agents_failed'] >= len(agents_dict.keys()):
        print(f'[ATTEMPTS] Configuration finished. All agents reached the max_n_attempts, '
              f'currently set up to {max_n_attempts}')

    if old_stats:
        stats = calculate_stats(daemon, **old_stats)
        print(f'[STATS] Finishing stats {daemon} writing: {time.time()},{",".join(stats.values())}')
        with open(filename, 'a') as file_:
            file_.write(f'{time.time()},{",".join(stats.values())}\n')
    else:
        regex_mem = r"ossec-syscheckd *([0-9]+)"
        stats = get_stats(daemon)
        ps = os.popen("ps -axo comm,rss | grep ossec-syscheckd | head -n1")
        cpu, mem = stats.pop('cpu'), re.match(regex_mem, ps.read()).group(1)
        print(f'[STATS] Finishing stats {daemon} writing: {time.time()},{cpu},{mem},'
              f'{",".join(stats.values())}')
        with open(filename, 'a') as file_:
            file_.write(f'{time.time()},{",".join(stats.values())}\n')


def protocol_detection(ossec_conf_path=WAZUH_CONF):
    """Detects the protocol configuration.

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
        return re.search(r'<protocol>(udp|tcp)</protocol>', open(ossec_conf_path).read()).group(1)
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
def test_initialize_stats_collector(eps, files, directory, buffer, case, modify_file, modify_all, restore_all):
    """Execute and launch all the necessary processes to check all the cases with all the specified configurations."""
    agents_dict = get_agents()
    attempts_info = Manager().dict({
        'start': False,
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
    stats_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stats',
                             f'{protocol}_{eps}eps-{files}files')
    if not os.path.exists(os.path.dirname(stats_dir)):
        os.mkdir(os.path.dirname(stats_dir))
    if not os.path.exists(stats_dir):
        os.mkdir(stats_dir)

    # If we are in case 1 or in case 2 and the number of files is 0, we will not execute the test since we cannot
    # modify the checksums because they do not exist
    if not (case == 1 and files == '0') and not (case == 2 and files == '0'):
        print(f'\n\n[SETUP] Setting up the environment for for case{case}_{protocol}-{eps}eps-{files}files')
        truncate_file(ALERT_FILE_PATH)
        # Only modify the configuration if case 0 is executing
        if case == Cases.case0.value:
            replace_conf(eps, directory, buffer)

        # Launch one process for agent due to FileMonitor restriction (block the execution)
        for agent_id in agents_dict.keys():
            filename = os.path.join(stats_dir, f"info-case{case}_{buffer}.csv")
            agents_checker.append(Process(target=agent_checker, args=(case, agent_id, agents_dict, filename,
                                                                      attempts_info, database_params,)))
            agents_checker[-1].start()

        # Block the test until one agent starts
        seconds = 0
        while not attempts_info['start']:
            if seconds >= max_time_for_agent_setup:
                raise TimeoutError('[ERROR] The agents are not ready')
            if seconds == 0:
                print(f'[SETUP] Waiting for agent attempt...')
            time.sleep(setup_environment_time)
            seconds += setup_environment_time

        # We started the stats collector as the agents are ready
        # print(f'[ENV] Started test for case{case}_{protocol}-{eps}eps-{files}files')
        state_collector_check = Process(target=state_collector, args=(case, agents_dict, buffer, stats_dir,
                                                                      attempts_info,))
        state_collector_check.start()
        for daemon in tested_daemons:
            filename = os.path.join(stats_dir, f"stats-{daemon}_case{case}_{buffer}.csv")
            stats_checker.append(Process(target=stats_collector, args=(filename, daemon, agents_dict, attempts_info,)))
            stats_checker[-1].start()
        while True:
            if not any([writer_.is_alive() for writer_ in stats_checker]) and \
                    not any([check_agent.is_alive() for check_agent in agents_checker]) and \
                    not state_collector_check.is_alive():
                print('[ENV] All processes are finished')
                break
            time.sleep(setup_environment_time)
    clean_environment()
