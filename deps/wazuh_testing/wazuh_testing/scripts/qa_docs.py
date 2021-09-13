import argparse
import logging
import os

from wazuh_testing.qa_docs.lib.config import Config
from wazuh_testing.qa_docs.lib.index_data import IndexData
from wazuh_testing.qa_docs.lib.sanity import Sanity
from wazuh_testing.qa_docs.doc_generator import DocGenerator
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError

VERSION = '0.1'
qactl_script_logger = Logging('QADOCS_SCRIPT', 'DEBUG', True)
CONFIG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'config.yaml')
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'output')
LOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'log')
SEARCH_UI_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'search_ui')


def start_logging(folder, debug_level=logging.INFO):
    LOG_PATH = os.path.join(folder, f"{os.path.splitext(os.path.basename(__file__))[0]}.log")
    if not os.path.exists(folder):
        os.makedirs(folder)
    logging.basicConfig(filename=LOG_PATH, level=debug_level)


def set_qadocs_logging(logging_level):
    if not logging_level:
        qadocs_logger = Logging(QADOCS_LOGGER)
        qadocs_logger.disable()
    else:
        qadocs_logger = Logging(QADOCS_LOGGER, logging_level, True)


def validate_parameters(parameters):
    qactl_script_logger.debug('Validating input parameters')

    # Check if the directory where the tests are located exist
    if parameters.test_dir:
        if not os.path.exists(parameters.test_dir):
            raise QAValueError(f"{parameters.test_dir} does not exist. Tests directory not found.",
                               qactl_script_logger.error)

    # Check that test_input name exists
    if parameters.test_input:
        doc_check = DocGenerator(Config(CONFIG_PATH, parameters.test_dir, '', parameters.test_input))
        if doc_check.locate_test() is None:
            raise QAValueError(f"{parameters.test_input} not found.",
                               qactl_script_logger.error)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--sanity-check', action='store_true', dest='sanity',
                        help="Run a sanity check")

    parser.add_argument('-v', '--version', action='store_true', dest="version",
                        help="Print qa-docs version")

    parser.add_argument('-t', action='store_true', dest='test_config',
                        help="Load test configuration.")

    parser.add_argument('-d', action='count', dest='debug_level',
                        help="Enable debug messages.")

    parser.add_argument('-I', dest='test_dir', required=True,
                        help="Path where tests are located.")

    parser.add_argument('-i', '--index-data', dest='index_name',
                        help="Indexes the data named as you specify as argument to elasticsearch.")

    parser.add_argument('-l', '--launch-ui', dest='launch_app',
                        help="Indexes the data named as you specify as argument and launch SearchUI.")

    parser.add_argument('-T', dest='test_input',
                        help="Parse the test that you pass as argument.")

    parser.add_argument('-o', dest='output_path',
                        help="Specifies the output directory for test parsed when -T is used.")

    parser.add_argument('-e', dest='test_exist',
                        help="Checks if test exists or not",)

    args = parser.parse_args()

    validate_parameters(args)

    if args.debug_level:
        # set_qadocs_logging('DEBUG')
        start_logging(LOG_PATH, logging.DEBUG)
    else:
        start_logging(LOG_PATH)
        # set_qadocs_logging('INFO')

    if args.test_exist:
        doc_check = DocGenerator(Config(CONFIG_PATH, args.test_dir, '', args.test_exist))
        if doc_check.locate_test() is not None:
            print("test exists")

    if args.version:
        print(f"qa-docs v{VERSION}")
    elif args.test_config:
        Config(CONFIG_PATH)
    elif args.sanity:
        sanity = Sanity(Config(CONFIG_PATH))
        qactl_script_logger.debug('Running sanity check')
        sanity.run()
    elif args.index_name:
        qactl_script_logger.debug(f"Indexing {args.index_name}")
        indexData = IndexData(args.index_name, Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
        indexData.run()
    elif args.launch_app:
        qactl_script_logger.debug(f"Indexing {args.index_name}")
        indexData = IndexData(args.launch_app, Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
        indexData.run()
        os.chdir(SEARCH_UI_PATH)
        qactl_script_logger.debug('Running SearchUI')
        os.system("ELASTICSEARCH_HOST=http://localhost:9200 npm start")
    else:
        if not args.test_exist:
            docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
            if args.test_input:
                qactl_script_logger.debug(f"Parsing the following test(s) {args.test_input}")
                if args.output_path:
                    qactl_script_logger.debug(f"{args.test_input}.json is going to be generated in {args.output_path}")
                    docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, args.output_path, args.test_input))
                else:
                    docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, '', args.test_input))
            else:
                qactl_script_logger.debug(f"Parsing all tests located in {args.test_dir}")
            qactl_script_logger.debug('Running QADOCS')
            docs.run()

    if __name__ == '__main__':
        main()
