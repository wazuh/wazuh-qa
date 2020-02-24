# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import shutil
import subprocess
import time
from copy import deepcopy
from enum import Enum
from multiprocessing import Process, Manager

import pandas as pd
import pytest

from wazuh_testing import logger
from wazuh_testing.fim import callback_realtime_added_directory
from wazuh_testing.tools import WAZUH_PATH, WAZUH_CONF, LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

root_dir = '/test'
tested_daemon = 'ossec-syscheckd'
state_collector_time = 1
state_path = os.path.join(WAZUH_PATH, 'var', 'run', 'ossec-agentd.state')
performance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stats', 'performance')
state_configuration = {
    "agentd.state_interval": state_collector_time,
    "syscheck.debug": 2
}


class Types(Enum):
    added = 'added'
    modified = 'modified'
    deleted = 'deleted'


# Fixtures

@pytest.fixture(scope='module')
def initial_clean():
    """Clean the environment."""
    clean_environment(stats=True)


@pytest.fixture(scope='module')
def modify_local_internal_options():
    """Replace the local_internal_options file"""
    with open(os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf'), 'w') as f:
        for conf, value in state_configuration.items():
            f.write(f'{conf}={value}\n')


# Functions


def replace_conf(syncro_eps, fim_eps):
    """Configure syscheck in realtime=yes."""
    directories_regex = r"<directories realtime=\"yes\">[\n\t ]*(TESTING_DIRECTORY)[\n\t ]*</directories>"
    fim_eps_regex = r"<syscheck>[\s\S\w]*<max_eps>[\n\t ]*([0-9]+)[\n\t ]*</max_eps>[\s\S\w]*<synchronization>"
    syncro_eps_regex = \
        r"<synchronization>[\s\S\w]*<max_eps>[\n\t ]*([0-9]+)[\n\t ]*</max_eps>[\s\S\w]*</synchronization>"

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'template_wazuh_conf.conf'), 'r') as f:
        content = f.read()
        new_config = re.sub(re.search(directories_regex, content).group(1), root_dir, content)
        new_config = re.sub(re.search(fim_eps_regex, content).group(1), str(fim_eps), new_config)
        new_config = re.sub(re.search(syncro_eps_regex, content).group(1), str(syncro_eps), new_config)

        with open(WAZUH_CONF, 'w') as conf:
            conf.write(new_config)
    # Set Read/Write permissions to agent.conf
    os.chmod(WAZUH_CONF, 0o666)


def get_total_disk_info(daemon):
    """Get total disk read/write info from /proc/[pid]/io.

    Parameters
    ----------
    daemon : str
        Daemon for whom we will get the stats.

    Returns
    -------
    tuple of str
        Total read value and total write value.
    """
    regex_rchar = r"rchar: ([0-9]+)"
    regex_wchar = r"wchar: ([0-9]+)"
    regex_syscr = r"syscr: ([0-9]+)"
    regex_syscw = r"syscw: ([0-9]+)"
    regex_read = r"read_bytes: ([0-9]+)"
    regex_write = r"write_bytes: ([0-9]+)"
    regex_cancelled_write_bytes = r"cancelled_write_bytes: ([0-9]+)"
    pid = subprocess.check_output(['pidof', daemon]).decode().strip().split(' ')

    with open(os.path.join(f'/proc/{pid[0]}/io'), 'r') as io_info:
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
    pid = subprocess.check_output(['pidof', daemon]).decode().strip().split(' ')
    cpu_file = f"/proc/{pid[0]}/stat"
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


def create_long_path(length, path_name):
    """Create the specified tree of directories.

    Parameters
    ----------
    length : int or str
        Length of the entire path.
    path_name : str
        Root directory.

    Returns
    -------
    path_name : str
        Created path.
    """
    path_name = os.path.join("/", "test", path_name)
    length = int(length)

    if length == 20:
        os.makedirs(os.path.join(path_name, "a" * (length - len(path_name) - 1)), exist_ok=True)
    elif length == 128:
        path_name = os.path.join(path_name, "a" * 64)
        os.makedirs(os.path.join(path_name, "a" * (length - len(path_name) - 1)), exist_ok=True)
    elif length == 2048:
        for _ in range(0, int(length / 128) - 1):
            path_name = os.path.join(path_name, "a" * 128)

        path_name = os.path.join(path_name, "a" * (length - len(path_name) - 1))
        os.makedirs(path_name, exist_ok=True)

    return path_name


def find_ossec_log(regex=None, strlog=None):
    """Find in the ossec.log the specified strlog and return the first group if match with the regex.

    Parameters
    ----------
    regex : str
        Regular expression to be matched.
    strlog : str
        String to be found in the ossec.log.

    Returns
    -------
    str or None
        First group of match or None.
    """
    try:
        head = subprocess.Popen(["cat", LOG_FILE_PATH], stdout=subprocess.PIPE)
        grep = subprocess.check_output(["grep", strlog], stdin=head.stdout).decode().strip()
        return re.search(regex, grep).group(1)
    except (AttributeError, subprocess.CalledProcessError):
        return None


def create_n_files(path_name, num_files=1000, file_size=1024):
    """Create the specified number of files with the custom size in the specified path.

    Parameters
    ----------
    path_name : str
        Parent dir of the new files.
    num_files : int or str
        Number of new files.
    file_size : int or str
        Size of the new files.
    """
    num_files, file_size = int(num_files), int(file_size)
    for i in range(0, num_files):
        with open(os.path.join(path_name, f"file_{str(i)}"), 'w+') as fd:
            fd.write('\0' * file_size * 1024)


def modify_n_files(path_name, num_files=1000):
    """Modify the specified number of files in the specified path.

    Parameters
    ----------
    path_name : str
        Parent dir of the modified files.
    num_files : int
        Number of modified files.
    """
    for i in range(0, int(num_files)):
        with open(os.path.join(path_name, f"file_{str(i)}"), 'w+') as fd:
            fd.write('')


def delete_n_files(path_name, num_files=1000):
    """Delete the specified number of files in the specified path.

    Parameters
    ----------
    path_name : str
        Parent dir of the deleted file.
    num_files : int
        Number of deleted files.
    """
    for i in range(0, int(num_files)):
        subprocess.call(["rm", os.path.join(path_name, f"file_{str(i)}")])


def detect_syscheck_version():
    if not os.path.exists(os.path.join(WAZUH_PATH, 'queue', 'fim')):
        return 'rbtree'
    else:
        with open(WAZUH_CONF, 'r') as wazuh_conf:
            if re.search(r'<database>[\n\t ]*memory[\n\t ]*</database>', wazuh_conf.read()):
                return 'sqlitemem'
            else:
                return 'sqlitedisk'


def clean_environment(stats=False):
    """Remove the stats files and remove the testing dir.

    Parameters
    ----------
    stats : bool
        If True, the stats files must be deleted.
    """
    if stats:
        shutil.rmtree(performance_dir, ignore_errors=True)
    shutil.rmtree(root_dir, ignore_errors=True)


def state_collector(state_filename, configuration, state_status):
    try:
        state_df = pd.read_csv(state_filename)
    except FileNotFoundError:
        state_df = pd.DataFrame(columns=['configuration', 'seconds', 'last_keepalive', 'msg_count', 'msg_sent',
                                         'control_count', 'state'])
    last_keep_regex = r"last_keepalive='([0-9 -:]+)'"
    msg_count_regex = r"msg_count='([0-9]+)'"
    msg_sent_regex = r"msg_sent='([0-9]+)'"

    while not state_status['stop']:
        with open(state_path, 'r') as state_file:
            content = state_file.read()
            last_keep = re.search(last_keep_regex, content).group(1)
            msg_count = re.search(msg_count_regex, content).group(1)
            msg_sent = re.search(msg_sent_regex, content).group(1)
            state_df.loc[len(state_df)] = [configuration, time.time(), last_keep, msg_count, msg_sent,
                                           str(int(msg_count) - int(msg_sent)), state_status['state']]
        time.sleep(state_collector_time)
    state_df.to_csv(state_filename, index=False)
    state_status['finish'] = True


def scan_integrity_test(fim_df, format, configuration, integrity_df, fim_type='scan'):
    """Get the stats when the scan and integrity is running.

    Parameters
    ----------
    fim_df : Pandas DataFrame
        DataFrame that contains the stats.
    format: str
        String with the current configuration
    configuration : dict
        Dict with the current configuration
    integrity_df : Pandas DataFrame, optional
        DataFrame that contains the integrity stats.
    fim_type : str, optional
        scan or integrity.
    """
    time_printing, pause, time_fim = 0, 0, None
    stats = get_stats(tested_daemon)
    old_stats = deepcopy(stats)
    logger.info(
        f"[SCAN] Test {fim_type} with {str(configuration['path_length'])} path length, {configuration['number_files']}"
        f" files and {configuration['file_size']} KB file size")

    while time_fim is None:
        diff = calculate_stats(old_stats, stats)
        old_stats = deepcopy(stats)
        logger.info(diff)
        if fim_type == 'scan':
            time_fim = find_ossec_log(r".*during: ([0-9]+\.[0-9]+) sec", "fim_print_info")
        elif fim_type == 'integrity':
            time_fim = find_ossec_log(r".*Time: ([0-9]+\.[0-9]+) seconds.", "Finished calculating FIM integrity")
        else:
            raise AttributeError(f'Invalid type detected: {fim_type}')

        fim_df.loc[len(fim_df)] = [format, str(time_printing), *list(diff.values()), fim_type]
        if time_fim is not None:
            integrity_df.loc[len(integrity_df)] = [format, fim_type, str(time_fim)]
            break
        time_printing += 1
        time.sleep(1)
        stats = get_stats(tested_daemon)


def process_manager(test_name, path_name, n_files, file_size=0):
    """Create the correct process for the current test.

    Parameters
    ----------
    test_name : str
        Current test_name (Types).
    path_name : str
        Root directory.
    n_files : int
        Number of files for this test.
    file_size : int, optional
        File size for this test.

    Returns
    -------
    Process
        Created process for join it.
    """
    if test_name == Types.added.value:
        FileMonitor(LOG_FILE_PATH).start(callback=callback_realtime_added_directory)
        process = Process(target=create_n_files, args=(path_name, n_files, file_size,))
    elif test_name == Types.modified.value:
        process = Process(target=modify_n_files, args=(path_name, n_files,))
    elif test_name == Types.deleted.value:
        process = Process(target=delete_n_files, args=(path_name, n_files,))
    else:
        raise AttributeError(f'Invalid type detected: {test_name}')

    process.start()
    return process


def time_manager(events, last_count, time_start, time_out, n_files):
    """Control the timer for realtime tests.

    Parameters
    ----------
    events : int
        Number of events already caught.
    last_count : int
        Number of events previously caught.
    time_start : float
        Start timestamp.
    time_out : int
        Current time_out.
    n_files : int
        Number of files for this test.

    Returns
    -------
    list
        List wìth the current count of events, with the last (previous count), with the final time and the current
        time_out.

    """
    count = int(events)
    if count - last_count > 0:
        time_out = 5
    else:
        time_out -= 1
    last_count = count

    time_fim = 0
    if count >= int(n_files) and int(time_out) == 0:
        time_finish = time.time()
        time_fim = time_finish - time_start

    return count, last_count, time_fim, time_out


def real_test(test_type, real_df, integrity_df, format, configuration):
    """Get the stats when realtime tests are running.

    Parameters
    ----------
    test_type : str
        Specify the type of the test.
    real_df : Pandas DataFrame
        DataFrame that contains the stats.
    integrity_df : Pandas DataFrame, optional
        DataFrame that contains the integrity stats.
    format: str
        String with the current configuration.
    configuration : dict
        Dict with the current configuration.
    """
    started = False
    process, grep_name = None, None
    time_printing, time_start, time_fim, count, last_count = 0, 0, 0, 0, 0
    time_out = 5
    grep_name = f'"mode":"real-time","type":"{test_type}"'
    stats = get_stats(tested_daemon)
    old_stats = deepcopy(stats)
    logger.info(
        f"[REAL] Test {test_type} with {configuration['path_length']} path length, {configuration['real_number_files']} "
        f"files and {configuration['file_size']} KB file size")

    while True:
        diff = calculate_stats(old_stats, stats)
        old_stats = deepcopy(stats)
        logger.info(diff)
        if not started:
            last_count = 0
            started = True
            path_name = create_long_path(configuration['path_length'], "real")
            time_start = time.time()
            process = process_manager(test_type, path_name, configuration['real_number_files'],
                                      configuration['file_size'])
        else:
            head = subprocess.Popen(["cat", LOG_FILE_PATH], stdout=subprocess.PIPE)
            grep = subprocess.Popen(["grep", grep_name], stdin=head.stdout, stdout=subprocess.PIPE)
            events = int(subprocess.check_output(["wc", "-l"], stdin=grep.stdout).decode().strip())
            count, last_count, time_fim, time_out = time_manager(events=events, last_count=last_count,
                                                                 time_out=time_out, time_start=time_start,
                                                                 n_files=configuration['real_number_files'])

        real_df.loc[len(real_df)] = [format, str(time_printing), *list(diff.values()), test_type]
        if time_fim:
            integrity_df.loc[len(integrity_df)] = [format, test_type, str(time_fim)]
        if time_out == 0:
            logger.warning(f"Timeout: Event read {str(count)} last: {str(last_count)}")
            break
        logger.info(f"[{test_type}] Writing info {str(time_printing)} Events: {str(count)}/"
                    f"{configuration['real_number_files']}")

        stats = get_stats(tested_daemon)
        time_printing += 1
        time.sleep(1)
    logger.info(f'[REAL] Time FIM: {time_fim}')
    if process:
        process.join()


@pytest.mark.parametrize('number_files', [
    '1', '1000', '100000'
])
@pytest.mark.parametrize('path_length', [
    '20', '128', '2048'
])
@pytest.mark.parametrize('file_size', [
    '1', '10', '100'
])
@pytest.mark.parametrize('eps', [
    {'syncro_eps': '10', 'fim_eps': '200'}
])
@pytest.mark.parametrize('mode', [
    'real-time'
])
def test_performance(mode, file_size, eps, path_length, number_files, initial_clean, modify_local_internal_options):
    """Execute and launch all the necessary processes to check all the cases with all the specified configurations."""
    replace_conf(eps['syncro_eps'], eps['fim_eps'])
    branch = detect_syscheck_version()
    os.makedirs(performance_dir, exist_ok=True)
    fconfiguration = f'{number_files}files_{path_length}length_{file_size}size'
    configuration = {
        'file_size': file_size,
        'path_length': path_length,
        'number_files': number_files,
        'real_number_files': 6000,
        'mode': mode
    }
    state_status = Manager().dict({'stop': False, 'finish': False, 'state': 'scan'})
    state_filename = os.path.join(performance_dir, f"{branch}_agentd_state.csv")
    integrity_filename = os.path.join(performance_dir, f"{branch}_time_checksum_integrity.csv")
    data_filename = os.path.join(performance_dir, f'{branch}_stats.csv')
    try:
        integrity_df = pd.read_csv(integrity_filename)
    except FileNotFoundError:
        integrity_df = pd.DataFrame(columns=['configuration', 'stage', 'duration(s)'])
    data_df = pd.DataFrame(columns=['configuration', 'seconds', 'cpu(%)', 'mem(KB)', 'rchar(KB/s)', 'wchar(KB/s)',
                                    'syscr(Input/s)', 'syscw(Output/s)', 'read_bytes(KB/s)', 'write_bytes(KB/s)',
                                    'cancelled_write_bytes(KB)', 'stage'])

    # Stop Wazuh
    control_service(daemon=tested_daemon, action='stop')
    check_daemon_status(daemon=tested_daemon, running=False)

    # Create number_files
    path_name = create_long_path(path_length, "scan")
    create_n_files(path_name, number_files, file_size)

    # Start Wazuh
    truncate_file(LOG_FILE_PATH)
    control_service(daemon=tested_daemon, action='start')
    check_daemon_status(daemon=tested_daemon, running=True)

    # Start state collector
    state_process = Process(target=state_collector, args=(state_filename, fconfiguration, state_status,))
    state_process.start()

    # Test Scan
    scan_integrity_test(fim_df=data_df, format=fconfiguration, configuration=configuration, integrity_df=integrity_df,
                        fim_type=state_status['state'])

    # Test Integrity
    state_status['state'] = 'integrity'
    scan_integrity_test(fim_df=data_df, format=fconfiguration, integrity_df=integrity_df, configuration=configuration,
                        fim_type=state_status['state'])

    # Test real-time (added, modified, deleted)
    truncate_file(LOG_FILE_PATH)
    state_status['state'] = Types.added.value
    real_test(state_status['state'], format=fconfiguration, real_df=data_df, integrity_df=integrity_df,
              configuration=configuration)
    truncate_file(LOG_FILE_PATH)
    state_status['state'] = Types.modified.value
    real_test(state_status['state'], format=fconfiguration, real_df=data_df, integrity_df=integrity_df,
              configuration=configuration)
    truncate_file(LOG_FILE_PATH)
    state_status['state'] = Types.deleted.value
    real_test(state_status['state'], format=fconfiguration, real_df=data_df, integrity_df=integrity_df,
              configuration=configuration)

    # Finishing
    state_status['stop'] = True
    while not state_status['finish']:
        time.sleep(0.1)
    state_process.join()
    integrity_df.to_csv(integrity_filename, index=False)
    data_df.to_csv(data_filename, index=False)

    # Clean environment
    clean_environment()
