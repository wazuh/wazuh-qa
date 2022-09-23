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


def syslog_simulator(parameters):
    """Run the syslog simulator tool.

    Args:
        parameters (dict): Script parameters.
    """
    python_executable = sys.executable
    run_parameters = f"{python_executable} {SYSLOG_SIMULATOR} "
    run_parameters += f"-a {parameters['address']} " if 'address' in parameters else ''
    run_parameters += f"-e {parameters['eps']} " if 'eps' in parameters else ''
    run_parameters += f"--protocol {parameters['protocol']} " if 'protocol' in parameters else ''
    run_parameters += f"-n {parameters['messages_number']} " if 'messages_number' in parameters else ''
    run_parameters += f"-m {parameters['message']} " if 'message' in parameters else ''
    run_parameters = run_parameters.strip()

    # Run the syslog simulator tool with custom parameters
    subprocess.call(run_parameters, shell=True)
