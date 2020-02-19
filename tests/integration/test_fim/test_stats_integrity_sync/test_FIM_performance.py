# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import shutil
import subprocess
import time
from multiprocessing import Process

import pandas as pd
import pytest

from wazuh_testing import logger
from wazuh_testing.tools import WAZUH_PATH, WAZUH_CONF, LOG_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service, check_daemon_status

root_dir = '/test'
tested_daemon = 'ossec-syscheckd'
performance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stats', 'performance')


# Fixtures

@pytest.fixture(scope='module')
def initial_clean():
    """Clean the environment."""
    clean_environment(stats=True)


@pytest.fixture(scope='module')
def replace_conf():
    directories_regex = r"<directories realtime=\"yes\">[\n\t ]*(TESTING_DIRECTORY)[\n\t ]*</directories>"

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'template_wazuh_conf.conf'), 'r') as f:
        content = f.read()
        new_config = re.sub(re.search(directories_regex, content).group(1), root_dir, content)

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
        Total read value and total write value
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
    regex_mem = rf"{daemon} *([0-9]+)"
    ps = subprocess.Popen(["ps", "-axo", "comm,rss"], stdout=subprocess.PIPE)
    grep = subprocess.Popen(["grep", daemon], stdin=ps.stdout, stdout=subprocess.PIPE)
    head = subprocess.check_output(["head", "-n1"], stdin=grep.stdout).decode().strip()
    io_stats = get_total_disk_info(daemon)

    return {
        'cpu': str(float(get_total_cpu_info(daemon)) - float(cpu)),
        'mem': re.match(regex_mem, head).group(1),
        'rchar': str(float(io_stats['rchar']) - float(rchar)),
        'wchar': str(float(io_stats['wchar']) - float(wchar)),
        'syscr': str(float(io_stats['syscr']) - float(syscr)),
        'syscw': str(float(io_stats['syscw']) - float(syscw)),
        'read_bytes': str(float(io_stats['read_bytes']) - float(read_bytes)),
        'write_bytes': str(float(io_stats['write_bytes']) - float(write_bytes)),
        'cancelled_write_bytes': str(float(io_stats['cancelled_write_bytes']) - float(cancelled_write_bytes))
    }


def create_long_path(length, path_name):
    path_name = os.path.join("/", "test", path_name)

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


def tail_ossec_fim_print_info():
    regex_tail = r".*during: ([0-9]+\.[0-9]+) sec"
    cat_ossec = subprocess.Popen(["cat", LOG_FILE_PATH], stdout=subprocess.PIPE)
    grep_ossec = subprocess.Popen(["grep", "fim_print_info"], stdin=cat_ossec.stdout, stdout=subprocess.PIPE)
    head_ossec = subprocess.check_output(["head", "-n1"], stdin=grep_ossec.stdout).decode().strip()

    return 0.0 if head_ossec == "" else float(re.match(regex_tail, head_ossec).group(1))


def tail_ossec_fim_sync_checksum():
    regex_tail = r".*Time: ([0-9]+\.[0-9]+) seconds."
    cat_ossec = subprocess.Popen(["cat", LOG_FILE_PATH], stdout=subprocess.PIPE)
    grep_ossec = subprocess.check_output(["grep", "Finished calculating FIM integrity"], stdin=cat_ossec.stdout
                                         ).decode().strip()

    return False if grep_ossec == "" else float(re.match(regex_tail, grep_ossec).group(1))


def create_n_files(path_name, num_files=1000, file_size=1024):
    for i in range(0, num_files):
        with open(os.path.join(path_name, f"file_{str(i)}"), 'w+') as fd:
            fd.write('\0' * file_size * 1024)


def modify_n_files(path_name, num_files=1000):
    for i in range(0, num_files):
        with open(os.path.join(path_name, f"file_{str(i)}"), 'w+') as fd:
            fd.write('')


def delete_n_files(path_name, num_files=1000):
    for i in range(0, num_files):
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
    if stats:
        shutil.rmtree(performance_dir, ignore_errors=True)
    shutil.rmtree(root_dir, ignore_errors=True)


def scan_test(scan_df, length, n_files, file_size):
    time_printing, pause = 0, 0
    logger.info(
        f"[SCAN] Test scan with {str(length)} path length, {str(n_files)} files and {str(file_size)} KB file size")
    previous_stats = get_stats(daemon=tested_daemon)

    while True:
        stats = calculate_stats(daemon=tested_daemon, **previous_stats)
        logger.info(stats)
        time_fim = tail_ossec_fim_print_info()
        if time_fim > 0:
            scan_df.loc[len(scan_df)] = [str(time_printing), *list(stats.values()), time_fim, 'scan']
            break

        if any(float(stat) != 0 for stat in stats.values()):
            scan_df.loc[len(scan_df)] = [str(time_printing), *list(stats.values()), str(0.0), 'scan']

        previous_stats = get_stats(daemon=tested_daemon)
        time_printing += 1
        time.sleep(1)


def integrity_test(data_df, integrity_df, length, n_files, file_size):
    time_printing = 0
    logger.info(
        f"[INTEGRITY] Test integrity with {str(length)} path length, {str(n_files)} files and {str(file_size)} KB file "
        f"size")
    previous_stats = get_stats(daemon=tested_daemon)

    while True:
        stats = calculate_stats(daemon=tested_daemon, **previous_stats)
        logger.info(stats)

        time_integrity = tail_ossec_fim_sync_checksum()
        if time_integrity is not False:
            integrity_df.loc[len(integrity_df)] = [str(n_files), str(length), str(file_size), str(time_integrity)]
            break

        if any(float(stat) != 0 for stat in stats.values()):
            data_df.loc[len(data_df)] = [str(time_printing), *list(stats.values()), str(time_integrity), 'integrity']

        previous_stats = get_stats(daemon=tested_daemon)
        time_printing += 1
        time.sleep(1)


def real_test(test_name, real_df, length, n_files, file_size):
    started = False
    process, grep_name = None, None
    time_printing, time_start, time_fim, last_count = 0, 0, 0, 0
    time_out = 5

    logger.info(
        f"[REAL] Test {test_name} with {str(length)} path length, {str(n_files)} files and {str(file_size)} KB file "
        f"size")
    previous_stats = get_stats(daemon=tested_daemon)
    while True:
        stats = calculate_stats(daemon=tested_daemon, **previous_stats)
        logger.info(stats)
        if not started:
            last_count = 0
            started = True
            path_name = create_long_path(length, "real")
            time_start = time.time()
            if test_name == "Insert":
                grep_name = '"mode":"real-time","type":"added"'
                process = Process(target=create_n_files, args=(path_name, n_files, file_size,))
                process.start()
            elif test_name == "Update":
                grep_name = '"mode":"real-time","type":"modified"'
                process = Process(target=modify_n_files, args=(path_name, n_files,))
                process.start()
            elif test_name == "Delete":
                grep_name = '"mode":"real-time","type":"deleted"'
                process = Process(target=delete_n_files, args=(path_name, n_files,))
                process.start()
        else:
            head = subprocess.Popen(["cat", LOG_FILE_PATH], stdout=subprocess.PIPE)
            grep = subprocess.Popen(["grep", grep_name], stdin=head.stdout, stdout=subprocess.PIPE)
            events = subprocess.check_output(["wc", "-l"], stdin=grep.stdout).decode().strip()

            count = int(events)
            if count - last_count > 0:
                time_out = 5
            else:
                time_out -= 1
            last_count = count

            if count >= n_files and time_out == 0:
                time_finish = time.time()
                time_fim = time_finish - time_start

            if time_out == 0:
                logger.warning(f"Timeout: Event read {str(count)} last: {str(last_count)}")
                break

            logger.info(f"[{test_name}] Writing info {str(time_printing)} Events: {str(count)}/{str(n_files)}")

        if any(float(stat) != 0 for stat in stats.values()):
            real_df.loc[len(real_df)] = [str(time_printing), *list(stats.values()), time_fim, test_name]

        previous_stats = get_stats(daemon=tested_daemon)
        time_printing += 1
        time.sleep(1)
    logger.info(f'[REAL] Time FIM: {time_fim}')
    process.join()


@pytest.mark.parametrize('number_files', [
    1, 1000, 100000
])
@pytest.mark.parametrize('path_length', [
    20, 128, 2048
])
@pytest.mark.parametrize('file_size', [
    1, 10, 100
])
@pytest.mark.parametrize('mode', [
    'real-time'
])
def test_performance(mode, file_size, path_length, number_files, initial_clean, replace_conf):
    """Execute and launch all the necessary processes to check all the cases with all the specified configurations."""
    branch = detect_syscheck_version()
    os.makedirs(performance_dir, exist_ok=True)
    integrity_filename = os.path.join(performance_dir, "time_checksum_integrity.csv")
    data_filename = os.path.join(performance_dir, f'{branch}-{mode}-{str(number_files)}-files_{str(path_length)}'
                                                  f'-lenpath_{str(file_size)}-Kbsize.csv')
    try:
        integrity_df = pd.read_csv(integrity_filename)
    except FileNotFoundError:
        integrity_df = pd.DataFrame(columns=['files', 'length', 'size', 'time'])
    data_df = pd.DataFrame(columns=['seconds', 'cpu(%)', 'mem(KB)', 'rchar(KB/s)', 'wchar(KB/s)', 'syscr(Input/s)',
                                    'syscw(Output/s)', 'read_bytes(KB/s)', 'write_bytes(KB/s)',
                                    'cancelled_write_bytes(KB)', 'duration(s)', 'stage'])

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

    # Test Scan
    scan_test(scan_df=data_df, length=path_length, n_files=number_files, file_size=file_size)

    # Test Integrity
    integrity_test(data_df=data_df, integrity_df=integrity_df, length=path_length, n_files=number_files,
                   file_size=file_size)
    integrity_df.to_csv(integrity_filename, index=False)

    # Test real-time (added, modified, deleted)
    truncate_file(LOG_FILE_PATH)
    real_test('Insert', real_df=data_df, length=path_length, n_files=6000, file_size=file_size)
    truncate_file(LOG_FILE_PATH)
    real_test('Update', real_df=data_df, length=path_length, n_files=6000, file_size=file_size)
    truncate_file(LOG_FILE_PATH)
    real_test('Delete', real_df=data_df, length=path_length, n_files=6000, file_size=file_size)
    data_df.to_csv(data_filename, index=False)

    # Clean environment
    clean_environment()
