import argparse
from os.path import join, dirname, abspath

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
    parser.add_argument('-t', '--timeout', dest='timeout', action='store', default=15, type=int,
                        help='Insert API timeout')
    parser.add_argument('-c', '--configuration', dest='configuration', action='store', required=True, type=str,
                        help='Path to the configuration file')
    parser.add_argument('-kt', '--kibana-template', dest='kibana_template', action='store', required=True, type=str,
                        help='Path to the Kibana request template')
    parser.add_argument('-et', '--extraload-template', dest='extraload_template', action='store', required=True, type=str,
                        help='Path to the ExtraLoad request template')

    return parser.parse_args()


def main():
    options = get_arguments()

    main_logger = CustomLogger('wazuh_api_simulator', foreground=options.foreground).get_logger()

    try:
        configuration = yaml.safe_load(open(options.configuration))
        main_logger.info(f'Loaded configuration file: {configuration}')
    except OSError as e:
        main_logger.error(f'Could not load configuration file. Error: {e}')
        exit(1)

    HOST = configuration['remote']['host']
    PORT = configuration['remote']['port']

    if configuration['kibana']['enabled']:
        kibana_logger = CustomLogger('kibana_thread', foreground=options.foreground, tag='Kibana').get_logger()
        try:
            kibana_thread = APISimulator(HOST, PORT, request_template=options.kibana_template,
                                         frequency=options.frequency, timeout=options.timeout,
                                         external_logger=kibana_logger)
            kibana_thread.start()
        except Exception as kibana_exception:
            kibana_logger.error(f'Unhandled exception: {kibana_exception}')

    if configuration['extra_load']['enabled']:
        extra_logger = CustomLogger('extra_thread', foreground=options.foreground, tag='ExtraLoad').get_logger()
        try:
            request_percentage = configuration['extra_load']['api_requests_percentage']
            extra_load_thread = APISimulator(HOST, PORT, request_template=options.extraload_template,
                                             request_percentage=request_percentage, timeout=options.timeout,
                                             external_logger=extra_logger)
            extra_load_thread.start()
        except Exception as extra_exception:
            extra_logger.error(f'Unhandled exception: {extra_exception}')


if __name__ == '__main__':
    main()
