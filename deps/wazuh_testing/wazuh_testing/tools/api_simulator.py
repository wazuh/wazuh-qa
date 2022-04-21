import json
import logging
from base64 import b64encode
from threading import Thread, Event
from time import sleep, time

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThreadFilter(logging.Filter):
    def __init__(self, thread_name):
        super().__init__()
        self.thread_name = thread_name

    def filter(self, record):
        record.thread_name = self.thread_name
        return True


class CustomLogger:
    def __init__(self, name, file_path='/tmp/wazuh_api_simulator.log', foreground=False, tag='Main',
                 level=logging.INFO):
        logger = logging.getLogger(name)
        logger.addFilter(ThreadFilter(tag))
        logger_formatter = logging.Formatter('{asctime} {levelname}: [{thread_name}] {message}', style='{',
                                             datefmt='%Y/%m/%d %H:%M:%S')
        logging.basicConfig(filename=file_path, filemode='a', level=level,
                            format='%(asctime)s %(levelname)s: [%(thread_name)s] %(message)s',
                            datefmt='%Y/%m/%d %H:%M:%S')

        if foreground:
            ch = logging.StreamHandler()
            ch.setFormatter(logger_formatter)
            logger.addHandler(ch)

        self.logger = logger

    def get_logger(self):
        return self.logger


class APISimulator:
    def __init__(self, host, port, protocol='https', frequency=60, user='wazuh-wui', password='wazuh-wui',
                 external_logger=None, request_percentage=0, request_template=None):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.frequency = frequency
        self.logger = external_logger if external_logger else logging.getLogger('wazuh-api-requester')
        self.user = user
        self.password = password
        self.token = None
        self.requests = None
        self.request_percentage = request_percentage

        self.thread = None
        self.event = None

        self.base_url = f'{self.protocol}://{self.host}:{self.port}'
        self.load_template(request_template)
        self.validate_percentage()

    def load_template(self, template_file):
        try:
            self.requests = yaml.safe_load(open(template_file))['requests']
            self.logger.info(f'Loaded template in {template_file}')
        except OSError as file_error:
            self.logger.error(f'Could not load request template: {file_error}')
            exit(1)
        except yaml.YAMLError as yaml_error:
            self.logger.error(f'Failed to load request template: {yaml_error}')
            exit(1)

    def validate_percentage(self):
        if self.request_percentage == 0:
            return

        elif 5 > self.request_percentage > 90:
            self.logger.error('Invalid request percentage. It must be between 5 and 90. Current '
                              f'{self.request_percentage}')
            exit(1)

    def get_token(self):
        authenticate_url = '/security/user/authenticate'
        basic_auth = {'Content-Type': 'application/json',
                      'Authorization': f"Basic {b64encode(f'{self.user}:{self.password}'.encode()).decode()}"}

        for _ in range(10):
            try:
                self.logger.info('Trying to obtain API token')
                response = requests.post(f"{self.base_url}{authenticate_url}", headers=basic_auth, verify=False)
                if response.status_code != 200:
                    self.logger.error(f'Failed to obtain API token: {response.json()}')
                    self.logger.error('Retrying in 1s...')
                    sleep(1)
                else:
                    self.token = json.loads(response.content.decode())['data']['token']
                    return

            except Exception as token_exception:
                self.logger.error(f'An exception occurred trying to obtain API token: {token_exception}')
                self.logger.error('Retrying in 1s...')
                sleep(1)
        else:
            raise RuntimeError('Could not obtain an API token after 10 tries')

    def make_request(self, request, result=False):
        endpoint = f"{self.base_url}{request['endpoint']}"
        headers = {'Authorization': f'Bearer {self.token}'}
        if request['body']:
            headers['Content-Type'] = 'application/json'

        try:
            response = getattr(requests, request['method'])(endpoint, headers=headers, params=request['parameters'],
                                                            data=request['body'], verify=False)
            if result:
                return response

        except Exception as exception:
            self.logger.error(f'Unhandled exception: {exception}')
            self.logger.info('Waiting 5 seconds...')
            sleep(5)
            return

        if response.status_code == 401:
            self.logger.warning('API token expired')
            self.get_token()
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                response = getattr(requests, request['method'])(endpoint, headers=headers, params=request['parameters'],
                                                                data=request['body'], verify=False)
                if result:
                    return response

            except Exception as exception:
                self.logger.error(f'Unhandled exception: {exception}')
                self.logger.info('Waiting 5 seconds...')
                sleep(5)
                return

        self.logger.info(f"API request {request['endpoint']} | {response.status_code}")

    def _calculate_mrpm(self):
        data = {'endpoint': '/manager/api/config',
                'method': 'get',
                'parameters': {},
                'body': {}}

        try:
            self.logger.info('Attempting to obtain max API requests per minute')
            response = self.make_request(data, result=True)
            max_request = \
                json.loads(response.content.decode())['data']['affected_items'][0]['node_api_config']['access'][
                    'max_request_per_minute']
            self.logger.info(f'Current max requests per minute: {max_request}')
            return int(max_request * self.request_percentage / 100)
        except Exception as max_request_error:
            self.logger.error(f'Could not obtain max API requests per minute: {max_request_error}')
            exit(1)

    def _request_loop(self):
        if not self.requests:
            self.logger.info('There are no requests to do. Process aborted')
            exit(0)
        self.logger.info(f'{len(self.requests)} requests per loop')
        self.logger.info(f'Frequency: {self.frequency}')
        self.get_token()

        time_per_request = self.frequency / len(self.requests)
        max_rpm = self._calculate_mrpm() if self.request_percentage else 0
        minute_timer = time()
        request_per_minute = 0 if not max_rpm else 1

        while not self.event.is_set():
            for request in self.requests:
                if self.event.is_set():
                    break
                tic = time()
                self.make_request(request)
                request_per_minute += 1

                if not max_rpm:
                    time_left = time_per_request - (time() - tic)
                    if time_left > 0:
                        sleep(time_left)
                elif time() - minute_timer < 60 and request_per_minute > max_rpm:
                    waiting_time = 60 - (time() - minute_timer)
                    self.logger.info(f'Max requests per minute limit exceeded. Waiting {int(waiting_time)}s')
                    sleep(waiting_time)
                    minute_timer = time()
                    request_per_minute = 0
                elif time() - minute_timer >= 60:
                    minute_timer = time()
                    request_per_minute = 0

    def start(self):
        self.logger.info('Initializing process')
        self.event = Event()
        self.thread = Thread(target=self._request_loop)
        self.thread.start()

    def shutdown(self):
        self.logger.info('Attempting to finish process')
        self.event.set()
        self.thread.join()
        self.logger.info('Process finished')
