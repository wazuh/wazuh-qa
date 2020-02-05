# Needs installed in system: sysstat, bc

import os
import re
import time
from multiprocessing import Process, Manager
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack

import pytest

from wazuh_testing.tools import WAZUH_PATH, ALERT_FILE_PATH
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor

agent_conf = os.path.join(WAZUH_PATH, 'etc', 'shared', 'default', 'agent.conf')
state_path = os.path.join(WAZUH_PATH, 'var', 'run')
db_path = '/var/ossec/queue/db/wdb'
manager_ip = '172.19.0.100'
setup_environment_time = 1  # Seconds
state_collector_time = 5  # Seconds
max_time_for_agent_setup = 180  # Seconds
tested_daemons = ["wazuh-db", "ossec-analysisd", "ossec-remoted"]


def db_query(agent, query):
    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(db_path)

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
    regex_disk_rd_wr = r".* *[0-9]* *[0-9]* *([0-9]+.[0-9]+) *([0-9]+.[0-9]+) *[0-9]+.[0-9]+ *{}".format(daemon)
    # char 37 is %
    ps = os.popen('ps -axo comm,' + chr(37) + 'cpu,rss | grep \"' + daemon + '\" | head -n1').read()
    pidstat = os.popen('pidstat -d | grep ' + daemon + ' | head -n1').read()
    try:
        cpu, mem = re.match(regex_cpu, ps).group(1), re.match(regex_mem, ps).group(1)
        disk_rd, disk_wr = re.match(regex_disk_rd_wr, pidstat).group(1), re.match(regex_disk_rd_wr, pidstat).group(2)
        total_disk_info = get_total_disk_info(daemon)

        return [cpu, mem, disk_rd, disk_wr, total_disk_info[0], total_disk_info[1]]
    except AttributeError:
        pass


# Return n_attempts in sync_info table
def n_attempts(agent="001"):
    regex = r"ok \[{\"n_attempts\":([0-9]+)}\]"
    response = db_query(agent, 'SELECT n_attempts FROM sync_info')

    try:
        return int(re.match(regex, response).group(1))
    except AttributeError:
        raise AttributeError('[ERROR] Database locked!')


# Return n_completions in sync_info table
def n_completions(agent="001"):
    regex = r"ok \[{\"n_completions\":([0-9]+)}\]"
    response = db_query(agent, 'SELECT n_completions FROM sync_info')

    try:
        return int(re.match(regex, response).group(1))
    except AttributeError:
        raise AttributeError('[ERROR] Database locked!')


# Delete all database files
def dump_database(agent_id):
    db_query(agent_id, 'UPDATE sync_info SET n_attempts=0')
    db_query(agent_id, 'UPDATE sync_info SET n_completions=0')
    db_query(agent_id, 'DELETE FROM fim_entry')


def get_agents(client_keys='/var/ossec/etc/client.keys'):
    agent_regex = r'([0-9]+) [^!.+]+ .+ .+'
    agent_dict = dict()
    agent_ids = list()
    with open(client_keys, 'r') as keys:
        for line in keys.readlines():
            agent_ids.append(re.match(agent_regex, line).group(1))

    for agent_id in agent_ids:
        agent_dict[agent_id.zfill(3)] = Manager().dict({
            'start': 0.0,
            'check_info': False,
        })

    return agent_dict


def replace_conf(protocol, eps, directory, buffer):
    new_config = str()
    address_regex = r".*<address>([0-9.]+)</address>"
    directory_regex = r'.*<directories check_all=\"yes\">(.+)</directories>'
    eps_regex = r'.*<max_eps>([0-9]+)</max_eps>'
    protocol_regex = r'.*<protocol>([a-z]+)</protocol>'
    buffer_regex = r'<client_buffer><disabled>(yes|no)</disabled></client_buffer>'

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/template_agent.conf'), 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = re.sub(address_regex, '<address>' + manager_ip + '</address>', line)
            line = re.sub(directory_regex, '<directories check_all="yes">' + directory + '</directories>', line)
            line = re.sub(eps_regex, '<max_eps>' + eps + '</max_eps>', line)
            line = re.sub(protocol_regex, '<protocol>' + protocol + '</protocol>', line)
            line = re.sub(buffer_regex, '<client_buffer><disabled>' + buffer + '</disabled></client_buffer>', line)
            new_config += line

        with open(agent_conf, 'w') as conf:
            conf.write(new_config)
    # Set Read/Write permissions to agent.conf
    os.chmod(agent_conf, 0o666)


def check_all_n_completions(agents_list):
    """Return min value of n_completions between all agents
    """
    all_n_completions = list()
    for agent_id in list(agents_list):
        all_n_completions.append(n_completions(agent_id))

    return min(all_n_completions)


def state_collector(protocol, eps, files, process_pool):
    daemons_dict = {
        'ossec-analysisd': [['syscheck_events_decoded', 'syscheck_edps', 'dbsync_queue_usage',
                            'dbsync_messages_dispatched', 'dbsync_mdps', 'events_received', 'events_dropped',
                            'syscheck_queue_usage', 'event_queue_usage'], True],
        'ossec-remoted': [['queue_size', 'tcp_sessions', 'evt_count', 'discarded_count', 'recv_bytes'], True]
    }

    deleted = False
    while True:
        if process_pool['check_state_start']:
            for file in os.listdir(state_path):
                if file.endswith('.state'):
                    daemon = file.split(".")[0]
                    filename = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            f"stats/state_{daemon}_{protocol}_{eps}_{files}k.csv")
                    if os.path.exists(filename) and not deleted:
                        os.unlink(filename)
                        deleted = True
                    with open(filename, 'a') as state:
                        values = list()
                        for field in daemons_dict[str(daemon)][0]:
                            value = re.search(rf"{field}='([0-9]+)'",
                                              open(os.path.join(state_path, file), 'r').read(), re.MULTILINE)
                            if value:
                                values.append(value.group(1))
                        if daemons_dict[str(daemon)][1]:
                            state.write(f"{','.join(daemons_dict[str(daemon)][0])}\n")
                            daemons_dict[str(daemon)][1] = False
                        print(f'[INFO] Writing {daemon} state: {",".join(values)}')
                        state.write(f"{','.join(values)}\n")
            time.sleep(state_collector_time)
        if process_pool['check_state_finish']:
            process_pool['state_collector'] = True
            break
    print(f'[INFO] Finished state collector')


def stats_collector(filename, daemon, agent_id, agents_dict, process_pool):
    # Detect that the agent are been restarted
    def callback_detect_agent_restart(line):
        try:
            return re.match(rf'.*\"agent\":{{\"id\":\"({agent_id})\".*', line).group(1)
        except IndexError:
            pass

    agent_id = FileMonitor(ALERT_FILE_PATH).start(timeout=max_time_for_agent_setup,
                                                  callback=callback_detect_agent_restart).result()
    if agents_dict[agent_id]['start'] == 0.0:
        agents_dict[agent_id]['start'] = time.time()
        process_pool['check_state_start'] = True
        print(f'[INFO] Agent {agent_id} started at {agents_dict[agent_id]["start"]}')
        dump_database(agent_id)  # Delete all database files
    with open(filename, 'w') as file_:
        file_.write("seconds,cpu,ram,avg_disk_read,avg_disk_write,total_disk_read,total_disk_write\n")
        while check_all_n_completions(agents_dict.keys()) == 0:
            if n_attempts(agent_id) > 0:
                stats = get_stats(daemon)
                if stats:
                    cpu, ram, avg_disk_write, avg_disk_read = stats[:4]
                    print(f'[INFO] Stats {agent_id}_{daemon} writing: {time.time()},{cpu},{ram},{avg_disk_read},'
                          f'{avg_disk_write},,')
                    file_.write(f'{time.time()},{cpu},{ram},{avg_disk_read},{avg_disk_write},,\n')
                if n_completions(agent_id) > 0 and not agents_dict[agent_id]['check_info']:
                    info_collector(agents_dict[agent_id], agent_id, filename.replace(f'results_{daemon}', 'info'))
            time.sleep(setup_environment_time)
        if not agents_dict[agent_id]['check_info']:
            info_collector(agents_dict[agent_id], agent_id, filename.replace(f'results_{daemon}', 'info'))
    finish_stats_collector(agent_id, agents_dict, process_pool, daemon, filename)


def finish_stats_collector(agent_id, agents_dict, process_pool, daemon, filename):
    if check_all_n_completions(agents_dict.keys()) > 0:
        while True:
            stats = get_stats(daemon)
            process_pool['check_state_finish'] = True
            if stats and process_pool['state_collector']:
                print(f'[INFO] Finishing stats {agent_id}_{daemon} writing: {time.time()},{",".join(stats)}')
                with open(filename, 'a') as file_:
                    file_.write(f'{time.time()},{",".join(get_stats(daemon))}\n')
                break


def info_collector(agent, agent_id, filename):
    agent['check_info'] = True
    with open(filename, 'w') as info_agent:
        print(
            f"[INFO] Info {agent_id} writing: "
            f"{agent_id},{n_attempts(agent_id)},{n_completions(agent_id)},{agent['start']},"
            f"{time.time()},{time.time() - agent['start']}")
        info_agent.write("agent_id,n_attempts,n_completions,start_time,end_time,total_time\n")
        info_agent.write(f"{agent_id},{n_attempts(agent_id)},{n_completions(agent_id)},{agent['start']},"
                         f"{time.time()},{time.time() - agent['start']}\n")


@pytest.mark.parametrize('protocol, eps, files, directory, buffer', [
    ('udp', '200', '0', '/test0k', 'no'),
    ('tcp', '200', '0', '/test0k', 'no'),
    ('udp', '200', '5000', '/test5k', 'no'),
    ('udp', '5000', '5000', '/test5k', 'no'),
    ('tcp', '200', '5000', '/test5k', 'no'),
    ('tcp', '5000', '5000', '/test5k', 'no'),
    ('udp', '200', '50000', '/test50k', 'no'),
    ('udp', '5000', '50000', '/test50k', 'yes'),
    ('tcp', '200', '50000', '/test50k', 'no'),
    ('tcp', '5000', '50000', '/test50k', 'yes'),
    ('udp', '5000', '1000000', '/test1M', 'yes'),
    ('udp', '1000000', '1000000', '/test1M', 'yes'),
    ('tcp', '5000', '1000000', '/test1M', 'yes'),
    ('tcp', '1000000', '1000000', '/test1M', 'yes')
])
def test_initialize_stats_collector(protocol, eps, files, directory, buffer):
    agents_dict = get_agents()
    writers = list()
    process_pool = Manager().dict({
        'check_state_start': False,
        'check_state_finish': False,
        'state_collector': False
    })

    print('[INFO] Setting up the environment...')
    truncate_file(ALERT_FILE_PATH)
    replace_conf(protocol, eps, directory, buffer)

    print(f'[INFO] Starting test for {protocol}-{eps}-{files}')
    Process(target=state_collector, args=(protocol, eps, files, process_pool)).start()
    for daemon in tested_daemons:
        for agent_id, value in agents_dict.items():
            filename = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    f"stats/results_{daemon}_{protocol}_{eps}_{files}k.csv")
            writers.append(Process(target=stats_collector, args=(filename, daemon, agent_id, agents_dict,
                                                                 process_pool,)))
            writers[-1].start()
    while True:
        if len(writers) == len(tested_daemons) * len(agents_dict.keys()):
            if not any([writer_.is_alive() for writer_ in writers]):
                print('[INFO] All writers are finished')
                break
