import sys
import time
import socket
import struct
import subprocess


# engine timeouts
T_1 = 1

# engine vars
ENGINE_OUTPUT_PATH = '/tmp/filepath.txt'
ENGINE_PREFIX = '.*'
QUEUE = '1'
LOCATION = 'location'
ENGINE_BUILD_PATH = '/home/vagrant/wazuh/src/engine/build'
TEST_PATH = '/home/vagrant/wazuh/src/engine/test'
ASSETS_PATH = f"{TEST_PATH}/assets/"
KVDB_WIN_INPUT = f"{TEST_PATH}/kvdb_input_files/windows/win-security-categorization.json"
KVDB_PATH = '/tmp/win-security-categorization/'
OUTPUT_FOLDER = '/tmp/'

# subprocess reference
subprocess_engine = None


def run_engine(command):
    """Run the engine subprocess and do not wait for it.
    Args:
        command (string): Command to run.
    Returns:
        str: Command output.
    """
    global subprocess_engine
    print('INFO: Starting the engine subprocess.')

    if sys.platform == 'win32':
        run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        # pid = subprocess.Popen([sys.executable, "longtask.py"], creationflags=DETACHED_PROCESS).pid
    else:
        subprocess_engine = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE, close_fds=True)

    # wait till the engine is up
    time.sleep(1)


def kill_engine():
    """Kill the engine subprocess."""
    print(f"INFO: Terminating the engine subprocess {subprocess_engine}")
    subprocess_engine.kill()

def run_local_command_printing_output(command):
    if sys.platform == 'win32':
        run = subprocess.Popen(command, shell=True)
    else:
        run = subprocess.Popen(['/bin/bash', '-c', command])

    # Wait for the process to finish
    run.communicate()

    result_code = run.returncode

    if result_code != 0:
        raise Exception(f"The command {command} returned {result_code} as result code.")

def send_event_to_engine(event):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect(('127.0.0.1', 5054))

    # msg format -> queue:location_str:msg
    msg_formatted = QUEUE + ':' + LOCATION + ':' + event
    msg_tam = len(msg_formatted)
    msg_tam_little_endian = struct.pack('<I', msg_tam)

    # the engine's tcpEndpoint expects: header(msg size(little endian)) + event with the expected format
    encoded_msg = msg_tam_little_endian + msg_formatted.encode()
    client_socket.send(encoded_msg)
    print(f"INFO: Sending encoded event: {encoded_msg}")
