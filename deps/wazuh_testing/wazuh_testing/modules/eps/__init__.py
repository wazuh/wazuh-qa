
import socket
import subprocess
import sys

from wazuh_testing.tools import SIMULATE_AGENT, SYSLOG_SIMULATOR


# Timeouts
T_10 = 10
T_20 = 20
T_60 = 60
T_80 = 80

ANALYSISD_PREFIX = r'.*wazuh-analysisd.*'
MAILD_PREFIX = r'.*wazuh-maild.*'
# wazuh-analysisd.state file default update configuration
ANALYSISD_STATE_INTERNAL_DEFAULT = '5'
PERCENTAGE_PROCESS_MSGS = 0.95
QUEUE_SIZE = 16384
# Set logcollector message that the agent sents
LOGCOLLECTOR_MESSAGE = 'Invalid user random_user from 1.1.1.1 port 11111:Message number:'
TIMEFRAME_DEFAULT_VALUE = 10
UPPER_QUEUE_HALF_SIZE_LIMIT = 0.51
LOWER_QUEUE_HALF_SIZE_LIMIT = 0.49
LOGCOLLECTOR_CUSTOM_MESSAGE_1 = 'Mar 24 10:12:36 centos7 sshd[12249]: Invalid user random_user from 1.1.1.1 port 11111'
LOGCOLLECTOR_CUSTOM_MESSAGE_2 = 'Mar 24 10:12:36 centos7 sshd[12249]: Invalid user random_user from 2.2.2.2 port 22222'
LOGCOLLECTOR_CUSTOM_MESSAGE_3 = 'Mar 24 10:12:36 centos7 sshd[12249]: Invalid user random_user from 3.3.3.3 port 33333'


def find_in_file(string_to_search, filename):
    """Find a specific string in a file

    Args:
        string_to_search (str): Word to find in the file
    Returns:
        str: Line that match in file
    """
    with open(filename, 'r') as file:
        for _, line in enumerate(file):
            if string_to_search in line:
                return line


def simulate_agent_function(param):
    """Function to run the script simulate_agent.py

    Args:
        param (dict): Dictionary with script parameters
    """
    # Get IP address of the host
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)

    python_executable = sys.executable
    subprocess.call(f"{python_executable} {SIMULATE_AGENT} -a {ip_addr} -n {param['num_agent']} \
                    -m {param['modules']} -s {param['eps']} -t {param['time']} \
                    -f {param['msg_size']} -e {param['total_msg']} \
                    -k {param['disable_keepalive_msg']} -d {param['disable_receive_msg']} \
                    -c {param['enable_logcollector_msg_number']} -g {param['message']}", shell=True)


def syslog_simulator_function(param):
    """Function to run the script syslog_simulator.py

    Args:
        param (dict): Dictionary with script parameters
    """
    python_executable = sys.executable
    subprocess.call(f"{python_executable} {SYSLOG_SIMULATOR} -m {param['message']} -e {param['total_msg']} \
                    -f {param['msg_size']} -t {param['interval_burst_time']} -b {param['messages_per_burst']}",
                    shell=True)
