import os
import sys
import signal
import argparse


if sys.platform == 'win32':
    import win32api
    import win32con
    import pywintypes


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

monitored_directory = os.path.join("C:", os.sep, "stress_test") if sys.platform == 'win32' else os.path.join("/" "stress_test")
testreg = os.path.join('SOFTWARE', 'testreg', 'testreg')


def signal_handler(sig, frame):
    print("Signal received. Exiting...")
    sys.exit(0)


def create_files(test_files):
    for filename in test_files:
        with open(os.path.join(monitored_directory, filename), 'w+') as f:
            f.write('This is a test file')


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
            print("Creating registry key " + str(os.path.join(registry_class_name[key], subkey)))

            key = win32api.RegCreateKeyEx(key, subkey, win32con.KEY_ALL_ACCESS | arch)

            return key[0]  # Ignore the flag that RegCreateKeyEx returns
        except OSError as e:
            print(f"Registry could not be created: {e}")
        except pywintypes.error as e:
            print(f"Registry could not be created: {e}")


def main(num_files):
    if sys.platform == 'win32':
        for n_registry in range(1, num_files+1):
            h_key = create_registry(registry_parser[KEY], f'{testreg}{n_registry}', KEY_WOW64_64KEY)
    else:
        if not os.path.exists(monitored_directory):
            os.makedirs(monitored_directory)

        test_files = [f"Testing{i}.txt" for i in range(1, num_files+1)]
        create_files(test_files)


if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='File manipulation script')
    parser.add_argument('--num-files', type=int, default=5, help='Number of files to create')
    args = parser.parse_args()

    main(args.num_files)
