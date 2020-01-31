# Needs installed in system: sysstat, bc

import asyncio
import os
import re
import shutil
import time
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from multiprocessing import Process, Queue

import pytest

from wazuh_testing.tools import AGENT_CONF
from wazuh_testing.tools.services import control_service

tested_daemons = ["wazuh-db", "ossec-analysisd"]


def db_query(agent, query):
    WDB = '/var/ossec/queue/db/wdb'

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    msg = 'agent {0} sql {1}'.format(agent, query).encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    return sock.recv(length).decode(errors='ignore')


# Get total disk read/write info from /proc/[pid]/io
def get_total_disk_info(daemon="ossec-analysisd"):
    regex_write = r".*\n.*\n.*\n.*\n.*\nwrite_bytes: ([0-9]+)\n.*"
    regex_read = r".*\n.*\n.*\n.*\nread_bytes: ([0-9]+)\n.*\n.*"
    pid = os.popen('pidof ' + daemon).read().strip()

    with open(os.path.join(f'/proc/{pid}/io'), 'r') as io_info:
        info = io_info.read()
        total_read = float(re.match(regex_read, info).group(1)) / 1024  # KB
        total_write = float(re.match(regex_write, info).group(1)) / 1024  # KB

    return [str(total_read), str(total_write)]


# Get CPU, RAM, disk read and disk write stats using ps and pidstat
def get_stats(daemon):
    regex_cpu = r"{} *([0-9]+.[0-9]+) *[0-9]+".format(daemon)
    regex_mem = r"{} *[0-9]+.[0-9]+ *([0-9]+)".format(daemon)
    regex_disk_rd = r".*([0-9]+,[0-9]+) *[0-9]+,[0-9]+ *[0-9]+,[0-9]+ *{}".format(daemon)
    regex_disk_wr = r".*[0-9]+,[0-9]+ *([0-9]+,[0-9]+) *[0-9]+,[0-9]+ *{}".format(daemon)
    # char 37 is %
    ps = os.popen('ps -axo comm,' + chr(37) + 'cpu,rss | grep \"' + daemon + '\" | head -n1').read()
    pidstat = os.popen('pidstat -d | grep ' + daemon + ' | head -n1').read()
    cpu, mem = re.match(regex_cpu, ps).group(1), re.match(regex_mem, ps).group(1)
    disk_rd, disk_wr = re.match(regex_disk_rd, pidstat).group(1).replace(",", "."), re.match(
        regex_disk_wr, pidstat).group(1).replace(",", ".")

    total_disk_info = get_total_disk_info(daemon)

    return [cpu, mem, disk_wr, disk_rd, total_disk_info[0], total_disk_info[1]]


# Return n_attempts in sync_info table
def n_attempts(agent="001"):
    regex = r".*\n.*\n.*\"n_attempts\": ([0-9]+)\n.*\n.*"

    response = db_query(agent, 'SELECT n_attempts FROM sync_info')
    result = re.match(regex, response).group(1)

    return int(result)


# Return n_completions in sync_info table
def n_completions(agent="001"):
    regex = r".*\n.*\n.*\"n_completions\": ([0-9]+)\n.*\n.*"

    response = db_query(agent, 'SELECT n_completions FROM sync_info')
    result = re.match(regex, response).group(1)

    return int(result)


# Delete all database files
def dump_database():
    folder = '/var/ossec/queue/db/'

    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)

        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


# Create list of n agents
def get_agent_info(total_agents=1):
    agents_info = list()

    for agent_id in list(map(str, range(1, total_agents + 1))):
        agents_info.append({
            'id': agent_id.zfill(3),
            'n_attempts': 0,
            'n_completions': 0,
            'start': 0.0,
            'end': 0.0,
            'total': 0.0
        })

    return agents_info


def replace_conf(protocol, eps, directory):
    manager_ip = '10.0.0.15'

    new_config = str()
    address_regex = r".*<address>([0-9.]+)</address>"
    directory_regex = r'.*<directories check_all=\"yes\">(.+)</directories>'
    eps_regex = r'.*<max_eps>([0-9]+)</max_eps>'
    protocol_regex = r'.*<protocol>([a-z]+)</protocol>'

    with open('data/template_agent.conf', 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = re.sub(address_regex, '<address>' + manager_ip + '</address>', line)
            line = re.sub(directory_regex, '<directories check_all="yes">' + directory + '</directories>', line)
            line = re.sub(eps_regex, '<max_eps>' + eps + '</max_eps>', line)
            line = re.sub(protocol_regex, '<protocol>' + protocol + '</protocol>', line)
            new_config += line

        with open(AGENT_CONF, 'w') as agent_conf:
            agent_conf.write(new_config)


def check_all_n_attempts(agents_list):
    """Return max value of n_attempts between all agents
    """
    all_n_attempts = list()
    for agent in agents_list:
        all_n_attempts.append(n_attempts(agent['id']))

    return max(all_n_attempts)


def check_all_n_completions(agents_list):
    """Return min value of n_completions between all agents
    """
    all_n_completions = list()
    for agent in agents_list:
        all_n_completions.append(n_completions(agent['id']))

    return min(all_n_completions)


def setup_environment(protocol, eps, directory, agents_list):
    control_service('stop')
    dump_database()  # Delete all database files
    control_service('start')
    replace_conf(protocol, eps, directory)
    while check_all_n_attempts(agents_list) != 0:
        time.sleep(1)


def write_stats(daemon, file_name):
    # Medir tiempo fuera de esta funcion
    with open(file_name, 'a') as file_:
        file_.write("seconds,cpu,ram,avg_disk_read,avg_disk_write,total_disk_read,total_disk_write\n")
        while True:
            cpu, ram, avg_disk_write, avg_disk_read = get_stats(daemon)
            file_.write(f'{cpu},{ram},{avg_disk_read},{avg_disk_write},,\n')
            time.sleep(1)


def finish_write(filename, agents_list):
    complete = False

    while not complete:
        if check_all_n_completions(agents_list) != 0:
            complete = True  # Finishing
            with open(filename, 'a') as result_file:
                for daemon in tested_daemons:
                    cpu, ram, avg_disk_write, avg_disk_read, total_disk_read, total_disk_write = get_stats(daemon)

                    for agent in agents_list:
                        agent['end'] = time.time()
                        agent['total'] = agent['end'] - agent['start']
                        agent['n_attempts'] = n_attempts(agent['id'])
                        agent['n_completions'] = n_completions(agent['id'])
                        result_file.write(f',{cpu},{ram},{avg_disk_read},{avg_disk_write},{total_disk_read},'
                                          f'{total_disk_write}\n')

                        with open(filename.replace('results', 'info'), 'w') as info_agent:
                            info_agent.write("agent_id,n_attempts,n_completions,start_time,end_time,total_time\n")
                            info_agent.write(agent['id'] + "," + agent['n_attempts'] + "," +
                                             agent['n_attempts'] + "," + agent['n_completions'] + "," +
                                             agent['start'] + "," + agent['end'] + "," +
                                             agent['total'])
        time.sleep(5)


@pytest.mark.parametrize('protocol, eps', [
    ('udp', '1000'),
    ('tcp', '1000'),
    ('udp', '1000000'),
    ('tcp', '1000000'),
])
@pytest.mark.parametrize('files, directory', [
    ('10000', '/test10k'),
    ('20000', '/test20k'),
    ('50000', '/test50k'),
    ('100000', '/test100k'),
    ('200000', '/test200k'),
    ('500000', '/test500k'),
    ('1000000', '/test1M'),
])
def test_initialize_stats_collector(protocol, eps, files, directory):
    writers = list()
    closers = list()
    q = Queue()

    agents_list = get_agent_info(total_agents=3)
    setup_environment(protocol=protocol, eps=eps, directory=directory, agents_list=agents_list)

    print(f"[INFO] Starting test with {protocol}, {eps} eps and {files}k files")
    for agent in agents_list:
        agent['start'] = time.time()

    for daemon in tested_daemons:
        file_name = f"results_{daemon}_{protocol}_{eps}_{files}k.csv"
        writers.append(Process(target=write_stats(daemon=daemon, file_name=file_name), args=(q,)))
        closers.append(Process(target=finish_write(file_name, agents_list), args=(q,)))

    while True:
        if check_all_n_completions(agents_list) != 0:
            for writer, closer in zip(writers, closers):
                writer.join()
                closer.join()
            break
