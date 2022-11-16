import subprocess
import sys

from wazuh_testing import SYSLOG_SIMULATOR


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
    run_parameters += f"-m '{parameters['message']}' " if 'message' in parameters else ''
    run_parameters += f"--numbered-messages {parameters['numbered_messages']} " if 'numbered_messages' in parameters \
        else ''
    run_parameters += f"-p '{parameters['port']}' " if 'port' in parameters else ''
    run_parameters = run_parameters.strip()

    # Run the syslog simulator tool with custom parameters
    subprocess.call(run_parameters, shell=True)
