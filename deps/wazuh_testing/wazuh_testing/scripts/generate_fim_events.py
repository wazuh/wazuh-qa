import os
import random
import string
import time
import argparse
import sys
import shutil
import signal
if sys.platform == 'win32':
    import win32api
    import win32con
    import pywintypes

monitored_directory = os.path.join("C:", os.sep, "stress_test") if sys.platform == 'win32' else os.path.join("/" "stress_test")
if sys.platform == 'win32':
    registry_parser = {
        'HKEY_LOCAL_MACHINE': win32con.HKEY_LOCAL_MACHINE
    }

    registry_class_name = {
        win32con.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE'
    }

    registry_value_type = {
        win32con.REG_SZ: 'REG_SZ'
    }

    REG_SZ = win32con.REG_SZ
    KEY_WOW64_64KEY = win32con.KEY_WOW64_64KEY
    KEY_ALL_ACCESS = win32con.KEY_ALL_ACCESS
    RegOpenKeyEx = win32api.RegOpenKeyEx
    KEY = "HKEY_LOCAL_MACHINE"

testreg = os.path.join('SOFTWARE', 'testreg')
reg_value = 'value_name'


def signal_handler(sig, frame):
    print("Signal received. Exiting...")
    sys.exit(0)


def create_registry(key, subkey, arch):
    """Create a registry given the key and the subkey. The registry is opened if it already exists.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).

    Returns:
         str: the key handle of the new/opened key.
    """

    if sys.platform == 'win32':
        try:
            key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)

            return key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            print(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            print(f"Registry could not be created: {e}")


def delete_registry(key, subkey, arch):
    """Delete a registry key.

    Args:
        key (pyHKEY): the key of the registry (HKEY_* constants).
        subkey (str): the subkey (name) of the registry.
        arch (int): architecture of the registry (KEY_WOW64_32KEY or KEY_WOW64_64KEY).
    """
    if sys.platform == 'win32':

        try:
            key_h = win32api.RegOpenKeyEx(key, subkey, 0, win32con.KEY_ALL_ACCESS | arch)
            win32api.RegDeleteTree(key_h, None)
            win32api.RegDeleteKeyEx(key, subkey, samDesired=arch)
        except OSError as e:
            print(f"Couldn't remove registry key {str(os.path.join(registry_class_name[key], subkey))}: {e}")
        except pywintypes.error as e:
            print(f"Couldn't remove registry key {str(os.path.join(registry_class_name[key], subkey))}: {e}")


def modify_registry_value(key_h, value_name, type, value):
    """
    Modify the content of a registry. If the value doesn't not exists, it will be created.

    Args:
        key_h (pyHKEY): the key handle of the registry.
        value_name (str): the value to be set.
        type (int): type of the value.
        value (str): the content that will be written to the registry value.
    """
    if sys.platform == 'win32':
        try:
            win32api.RegSetValueEx(key_h, value_name, 0, type, value)
        except OSError as e:
            print(f"Could not modify registry value content: {e}")
        except pywintypes.error as e:
            print(f"Could not modify registry value content: {e}")


def generate_events(test_files, file_size, eps):
    events_produced = 0

    list_registry = [f'{testreg}{i}' for i in range(1, len(test_files)+1)]

    while events_produced < eps:
        if sys.platform == 'win32':
            random_string = ''.join(random.choice(string.ascii_letters) for _ in range(10))
            registry_to_modify = random.choice(list_registry)
            modify_registry_value(win32api.RegOpenKeyEx(registry_parser[KEY], registry_to_modify, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY), reg_value, REG_SZ, random_string)
        else:
            random_string = ''.join(random.choice(string.ascii_letters) for _ in range(file_size))
            file_to_modify = random.choice(test_files)
            with open(os.path.join(monitored_directory, file_to_modify), 'w+') as f:
                f.write(random_string)

        events_produced += 1

        random_string = ''.join(random.choice(string.ascii_letters) for _ in range(file_size))


def main(num_files, duration, eps, file_size):
    if not os.path.exists(monitored_directory):
        os.makedirs(monitored_directory)

    test_files = [f"Testing{i}.txt" for i in range(1, num_files+1)]

    start_time = time.time()

    while (time.time() - start_time) < duration:
        generate_events(test_files, file_size, eps)
        time.sleep(1)

    if sys.platform == 'win32':
        for n_registry in range(1, num_files+1):
            delete_registry(registry_parser[KEY], f'{testreg}{n_registry}', KEY_WOW64_64KEY)
    else:
        if os.path.exists(monitored_directory):
            for filename in test_files:
                os.remove(os.path.join(monitored_directory, filename))


if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='File manipulation script')
    parser.add_argument('--num-files', type=int, default=5, help='Number of files to create')
    parser.add_argument('--duration', type=int, default=10, help='Duration of script execution in seconds')
    parser.add_argument('--eps', type=int, default=10, help='Number of events per second')
    parser.add_argument('--file-size', type=int, default=1024, help='File size in Bytes')
    args = parser.parse_args()

    main(args.num_files, args.duration, args.eps, args.file_size)
