import argparse
from time import sleep

import yaml
from wazuh_testing.tools.api_simulator import CustomLogger, APISimulator


def get_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",
                                     description="Wazuh API load simulator",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--foreground', dest='foreground', action='store_true', default=False,
                        help='Enable logging in foreground mode')
    parser.add_argument('-fr', '--frequency', dest='frequency', action='store', default=60, type=int,
                        help='Insert Kibana API requests interval')
    parser.add_argument('-t', '--time', dest='time', action='store', default=60, type=int, required=True,
                        help='Time in seconds for the simulation')
    parser.add_argument('-l', '--log-path', dest='log_path', action='store', default='/tmp/wazuh_api_simulator.log',
                        required=True, type=str, help='Log path file destination')
    parser.add_argument('-c', '--configuration', dest='configuration', action='store', required=True, type=str,
                        help='Path to the configuration file')
    parser.add_argument('-kt', '--kibana-template', dest='kibana_template', action='store', required=True, type=str,
                        help='Path to the Kibana request template')
    parser.add_argument('-et', '--extraload-template', dest='extraload_template', action='store', required=True,
                        type=str, help='Path to the ExtraLoad request template')

    return parser.parse_args()


def main():
    options = get_arguments()

    main_logger = CustomLogger('wazuh_api_simulator', file_path=options.log_path,
                               foreground=options.foreground).get_logger()
    try:
        configuration = yaml.safe_load(open(options.configuration))
        main_logger.info(f'Loaded configuration file: {configuration}')
    except OSError as e:
        main_logger.error(f'Could not load configuration file. Error: {e}')
        exit(1)

    HOST = configuration['remote']['host']
    PORT = configuration['remote']['port']

    thread_list = []

    if configuration['extra_load']['enabled']:
        extra_logger = CustomLogger('extra_thread', file_path=options.log_path, foreground=options.foreground,
                                    tag='ExtraLoad').get_logger()
        try:
            request_percentage = configuration['extra_load']['api_requests_percentage']
            extra_load_thread = APISimulator(HOST, PORT, request_template=options.extraload_template,
                                             request_percentage=request_percentage, external_logger=extra_logger)
            extra_load_thread.start()
            thread_list.append(extra_load_thread)
        except Exception as extra_exception:
            extra_logger.error(f'Unhandled exception: {extra_exception}')

    if configuration['kibana']['enabled']:
        kibana_logger = CustomLogger('kibana_thread', file_path=options.log_path, foreground=options.foreground,
                                     tag='Kibana').get_logger()
        try:
            kibana_thread = APISimulator(HOST, PORT, request_template=options.kibana_template,
                                         frequency=options.frequency, external_logger=kibana_logger)
            kibana_thread.start()
            thread_list.append(kibana_thread)
        except Exception as kibana_exception:
            kibana_logger.error(f'Unhandled exception: {kibana_exception}')

    sleep(options.time)
    for thread in thread_list:
        thread.shutdown()


if __name__ == '__main__':
    main()
