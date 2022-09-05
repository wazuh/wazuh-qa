import socket
import subprocess
import sys

from wazuh_testing import SIMULATE_AGENT, SYSLOG_SIMULATOR


def simulate_agent(param):
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
                    -f {param['msg_size']} -e {param['num_messages']} \
                    -k {param['disable_keepalive_msg']} -d {param['disable_receive_msg']} \
                    -c {param['enable_logcollector_msg_number']} -g {param['message']}", shell=True)


def syslog_simulator(param):
    """Function to run the script syslog_simulator.py

    Args:
        param (dict): Dictionary with script parameters
    """
    python_executable = sys.executable
    subprocess.call(f"{python_executable} {SYSLOG_SIMULATOR} -m {param['message']} -e {param['num_messages']} \
                    -f {param['msg_size']} -t {param['interval_burst_time']} -b {param['messages_per_burst']}",
                    shell=True)
