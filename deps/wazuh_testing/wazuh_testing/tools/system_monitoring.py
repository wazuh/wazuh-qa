import yaml
import os
import time

from multiprocessing import Process, Manager
from collections import defaultdict
from lockfile import FileLock
from shutil import copyfile

from wazuh_testing import logger
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileTailer, QueueMonitor, make_callback


def new_process(fn):
    """Wrapper for enable multiprocessing inside a class

    Args:
        fn (callable): Function to be executed in a new thread

    Returns:
        wrapper
    """

    def wrapper(*args, **kwargs):
        thread = Process(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread

    return wrapper


class HostMonitor:
    """This class has the capability to monitor remote host. This monitoring consists of reading the specified files to
    check that the expected message arrives to them.

    If the goals are achieved, no exceptions will be raised and therefore the test will end properly and without
    failures.

    In contrast, if one or more of the goals is not covered, a timeout exception will be raised with a generic or a
    custom error message.
    """

    def __init__(self, inventory_path, messages_path, tmp_path, time_step=0.5):
        """Create a new instance to monitor any given file in any specified host.

        Args:
            inventory_path (str): Path to the hosts's inventory file.
            messages_path (str):  Path to the file where the callbacks, paths and hosts to be monitored are specified.
            tmp_path (str): Path to the temporal files.
            time_step (float, optional): Fraction of time to wait in every get. Defaults to `0.5`
        """
        self.host_manager = HostManager(inventory_path=inventory_path)
        self._queue = Manager().Queue()
        self._result = defaultdict(list)
        self._time_step = time_step
        self._file_monitors = list()
        self._file_content_collectors = list()
        self._tmp_path = tmp_path
        try:
            os.mkdir(self._tmp_path)
        except OSError:
            pass
        with open(messages_path, 'r') as f:
            self.test_cases = yaml.safe_load(f)

    def run(self, update_position=False):
        """This method creates and destroy the needed processes for the messages founded in messages_path.
        It creates one file composer (process) for every file to be monitored in every host."""
        for host, payload in self.test_cases.items():
            monitored_files = {case['path'] for case in payload}
            if len(monitored_files) == 0:
                raise AttributeError('There is no path to monitor. Exiting...')
            for path in monitored_files:
                output_path = f'{host}_{path.split("/")[-1]}.tmp'
                self._file_content_collectors.append(self.file_composer(host=host, path=path, output_path=output_path))
                logger.debug(f'Add new file composer process for {host} and path: {path}')
                self._file_monitors.append(self._start(host=host,
                                                       payload=[block for block in payload if block["path"] == path],
                                                       path=output_path))
                logger.debug(f'Add new file monitor process for {host} and path: {path}')

        while True:
            if not any([handler.is_alive() for handler in self._file_monitors]):
                for handler in self._file_monitors:
                    handler.join()
                for file_collector in self._file_content_collectors:
                    file_collector.terminate()
                    file_collector.join()
                self.clean_tmp_files()
                break
            time.sleep(self._time_step)
        self.check_result()
        return self.result()

    @new_process
    def file_composer(self, host, path, output_path):
        """Collects the file content of the specified path in the desired host and append it to the output_path file.
        Simulates the behavior of tail -f and redirect the output to output_path.

        Args:
            host (str): Hostname.
            path (str): Host file path to be collect.
            output_path (str): Output path of the content collected from the remote host path.
        """
        try:
            truncate_file(os.path.join(self._tmp_path, output_path))
        except FileNotFoundError:
            pass
        logger.debug(f'Starting file composer for {host} and path: {path}. '
                     f'Composite file in {os.path.join(self._tmp_path, output_path)}')
        tmp_file = os.path.join(self._tmp_path, output_path)
        while True:
            with FileLock(tmp_file):
                with open(tmp_file, "r+") as file:
                    content = self.host_manager.get_file_content(host, path).split('\n')
                    file_content = file.read().split('\n')
                    for new_line in content:
                        if new_line == '':
                            continue
                        if new_line not in file_content:
                            file.write(f'{new_line}\n')
                time.sleep(self._time_step)

    @new_process
    def _start(self, host, payload, path, encoding=None, error_messages_per_host=None, update_position=False):
        """Start the file monitoring until the QueueMonitor returns an string or TimeoutError.

        Args:
            host (str): Hostname
            payload (list,dict): Contains the message to be found and the timeout for it.
            path (str): Path where it must search for the message.
            encoding (str): Encoding of the file.
            error_messages_per_host (dict): Dictionary with hostnames as keys and desired error messages as values
        Returns:
            Instance of HostMonitor
        """
        tailer = FileTailer(os.path.join(self._tmp_path, path), time_step=self._time_step)
        try:
            if encoding is not None:
                tailer.encoding = encoding
            tailer.start()
            for case in payload:
                logger.debug(f'Starting QueueMonitor for {host} and message: {case["regex"]}')
                monitor = QueueMonitor(tailer.queue, time_step=self._time_step)
                try:
                    self._queue.put({host: monitor.start(timeout=case['timeout'],
                                                         callback=make_callback(pattern=case['regex'], prefix='.*'),
                                                         update_position=False
                                                         ).result()})
                except TimeoutError:
                    try:
                        self._queue.put({host: error_messages_per_host[host]})
                    except (KeyError, TypeError):
                        self._queue.put({
                            host: TimeoutError(f'Did not found the expected callback in {host}: {case["regex"]}')})
                logger.debug(f'Finishing QueueMonitor for {host} and message: {case["regex"]}')
        finally:
            tailer.shutdown()

        return self

    def result(self):
        """Get the result of HostMonitor

        Args:
            dict (dict): Dict that contains the host as the key and a list of messages as the values
        """
        return self._result

    def check_result(self):
        """Check if a TimeoutError occurred."""
        logger.debug('Checking results...')
        while not self._queue.empty():
            result = self._queue.get(block=True)
            for host, msg in result.items():
                if isinstance(msg, TimeoutError):
                    raise msg
                logger.debug(f'Received from {host} the expected message: {msg}')
                self._result[host].append(msg)

    def clean_tmp_files(self):
        """Remove tmp files."""
        logger.debug("Cleaning temporal files...")
        for file in os.listdir(self._tmp_path):
            tmp_file = os.path.join(self._tmp_path, file)
            if file.endswith(".log.tmp"):
                copyfile(tmp_file, os.path.join("/tmp", os.path.splitext(file)[0]))
            os.remove(tmp_file)
