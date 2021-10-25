# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import sys
import json
from datetime import datetime
from elasticsearch import Elasticsearch

from wazuh_testing.qa_docs.lib.config import Config
from wazuh_testing.qa_docs.lib.index_data import IndexData
from wazuh_testing.qa_docs.lib.sanity import Sanity
from wazuh_testing.qa_docs.lib.utils import run_local_command
from wazuh_testing.qa_docs.doc_generator import DocGenerator
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError

VERSION_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'VERSION.json')
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'schema.yaml')
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'output')
LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'log')
SEARCH_UI_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'search_ui')
qadocs_logger = Logging(QADOCS_LOGGER, 'INFO', True, os.path.join(LOG_PATH,
                        f"{datetime.today().strftime('%Y-%m-%d_%H-%M')}-qa-docs.log"))


def set_qadocs_logger_level(logging_level):
    """Set the QADOCS logger lever depending on the level specified by the user.

    Args:
        logging_level (string): Level used to initialize the logger.
    """
    if logging_level is None:
        qadocs_logger.disable()
    else:
        qadocs_logger.set_level(logging_level)

def set_parameters(args):
    # Set the qa-docs logger level
    if args.debug_level:
        set_qadocs_logger_level('DEBUG')

    # Deactivate the qa-docs logger if necessary.
    if args.no_logging:
        set_qadocs_logger_level(None)

def get_parameters():
    """Capture the script parameters

    Returns:
        argparse.Namespace: Object with the script parameters.
        argparse.ArgumentParser: Object with from the parser class.
    """
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    parser.add_argument('-s', '--sanity-check', action='store_true', dest='sanity',
                        help="Run a sanity check.")

    parser.add_argument('--no-logging', action='store_true', dest='no_logging',
                        help="Do not perform logging when running the tool.")

    parser.add_argument('-v', '--version', action='store_true', dest="version",
                        help="Print qa-docs version.")

    parser.add_argument('-d', '--debug', action='count', dest='debug_level',
                        help="Enable debug messages.")

    parser.add_argument('-I', '--tests-path', dest='tests_path',
                        help="Path where tests are located.")

    parser.add_argument('-t', '--tests', nargs='+', default=[], dest='test_names',
                        help="Parse the test(s) that you pass as argument.")

    parser.add_argument('--types', nargs='+', default=[], dest='test_types',
                        help="Parse the tests from type(s) that you pass as argument.")

    parser.add_argument('--modules', nargs='+', default=[], dest='test_modules',
                        help="Parse the tests from modules(s) that you pass as argument.")

    parser.add_argument('-i', '--index-data', dest='index_name',
                        help="Indexes the data named as you specify as argument to elasticsearch.")

    parser.add_argument('-l', '--launch-ui', dest='app_index_name',
                        help="Launch SearchUI using the index that you specify.")

    parser.add_argument('-il', dest='launching_index_name',
                        help="Indexes the data named as you specify as argument and launch SearchUI.")

    parser.add_argument('-o', dest='output_path',
                        help="Specifies the output directory for test parsed when `-t, --tests` is used.")

    parser.add_argument('-e', '--exist', nargs='+', default=[], dest='test_exist',
                        help="Checks if test(s) exist or not.",)

    return parser.parse_args(), parser


def check_incompatible_parameters(parameters):
    """Check the parameters that qa-docs receives and check any incompatibilities.

    Args:
        parameters (argparse.Namespace): The parameters that the tool receives.
    """
    default_run = parameters.test_types or parameters.test_modules
    api_run = parameters.index_name or parameters.app_index_name or parameters.launching_index_name
    test_run = parameters.test_names or parameters.test_exist

    if parameters.version and (default_run or api_run or parameters.tests_path or test_run):
        raise QAValueError('The -v, --version option must be run in isolation.',
                           qadocs_logger.error)

    if parameters.sanity and (default_run or api_run or test_run):
        raise QAValueError('The -s, --sanity-check option must be run with -I, --tests-path option.',
                           qadocs_logger.error)

    if parameters.tests_path is None and (default_run or test_run or parameters.sanity):
        raise QAValueError('The following options need the path where the tests are located: -t, --test, '
                           '  -e, --exist, --types, --modules, -s, --sanity-check. You must specify it by using '
                           '-I, --tests-path path_to_tests.',
                           qadocs_logger.error)

    if api_run and (test_run):
        raise QAValueError('The -e, -t options do not support API usage.',
                           qadocs_logger.error)

    if parameters.output_path and default_run:
        raise QAValueError('The -o parameter only works with -t, --tests options in isolation. The default output '
                           'path is generated within the qa-docs tool to index it and visualize it.',
                           qadocs_logger.error)

    if (parameters.test_types or parameters.test_modules) and test_run:
        raise QAValueError('The --types, --modules parameters parse the data so you can index it and visualize it. '
                           '-t, --tests get specific tests information.',
                           qadocs_logger.error)

    if parameters.no_logging and parameters.debug_level:
        raise QAValueError('You cannot specify debug level and no-logging at the same time.',
                           qadocs_logger.error)


def validate_parameters(parameters, parser):
    """Validate the parameters that qa-docs receives.

    Args:
        parameters (list): A list of input args.
    """
    qadocs_logger.debug('Validating input parameters')

    # If qa-docs runs without any parameter or just `-d` option, it raises an error and prints the help message.
    if len(sys.argv) < 2 or (len(sys.argv) < 3 and parameters.debug_level):
        parser.print_help()
        exit(1)

    check_incompatible_parameters(parameters)

    # Check if the directory where the tests are located exist
    if parameters.tests_path:
        if not os.path.exists(parameters.tests_path):
            raise QAValueError(f"{parameters.tests_path} does not exist. Tests directory not found.",
                               qadocs_logger.error)

    # Check that test_input name exists
    if parameters.test_names:
        doc_check = DocGenerator(Config(SCHEMA_PATH, parameters.tests_path, test_names=parameters.test_names))

        for test_name in parameters.test_names:
            if doc_check.locate_test(test_name) is None:
                raise QAValueError(f"{test_name} has not been not found in {parameters.tests_path}.", qadocs_logger.error)

    # Check that the index exists
    if parameters.app_index_name:
        es = Elasticsearch()
        try:
            es.count(index=parameters.app_index_name)
        except Exception as index_exception:
            raise QAValueError(f"Index exception: {index_exception}", qadocs_logger.error)

    # Check that modules selection is done within a test type
    if parameters.test_modules and len(parameters.test_types) != 1:
        raise QAValueError('The --modules option work when is only parsing a single test type. Use --types with just '
                           'one type if you want to parse some modules within a test type.',
                           qadocs_logger.error)

    qadocs_logger.debug('Input parameters validation completed')


def install_searchui_deps():
    """Install SearchUI dependencies if needed"""
    os.chdir(SEARCH_UI_PATH)
    if not os.path.exists(os.path.join(SEARCH_UI_PATH, 'node_modules')):
        qadocs_logger.info('Installing SearchUI dependencies')
        run_local_command("npm install")


def run_searchui(index):
    """Run SearchUI installing its dependencies if necessary"""
    install_searchui_deps()
    qadocs_logger.debug('Running SearchUI')

    run_local_command(f"npm --ELASTICHOST=http://localhost:9200 --INDEX={index} start")


def parse_data(args):
    """Parse the tests and collect the data."""
    if args.test_exist:
        doc_check = DocGenerator(Config(SCHEMA_PATH, args.tests_path, '', test_names=args.test_exist))

        doc_check.check_test_exists(args.tests_path)

    # Parse a list of tests
    elif args.test_names:
        qadocs_logger.info(f"Parsing the following test(s) {args.test_names}")

        # When output path is specified by user, a json is generated within that path
        if args.output_path:
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, args.output_path, test_names=args.test_names))
        # When no output is specified, it is printed
        else:
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, test_names=args.test_names))

    # Parse a list of test types
    elif args.test_types:
        qadocs_logger.info(f"Parsing the following test(s) type(s): {args.test_types}")

        # Parse a list of test modules
        if args.test_modules:
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                args.test_modules))
        else:
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types))

    # Parse the whole path
    else:
        if not (args.index_name or args.app_index_name or args.launching_index_name):
            qadocs_logger.info(f"Parsing all tests located in {args.tests_path}")
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH))
            docs.run()

    if args.test_types or args.test_modules or args.test_names:
        qadocs_logger.info('Running QADOCS')
        docs.run()


def index_and_visualize_data(args):
    """Index the data previously parsed and visualize it."""
    # Index the previous parsed tests into Elasticsearch
    if args.index_name:
        index_data = IndexData(args.index_name, OUTPUT_PATH)
        index_data.run()

    # Launch SearchUI with index_name as input
    elif args.app_index_name:
        # When SearchUI index is not hardcoded, it will be use args.app_index_name
        run_searchui(args.app_index_name)

    # Index the previous parsed tests into Elasticsearch and then launch SearchUI
    elif args.launching_index_name:
        qadocs_logger.debug(f"Indexing {args.launching_index_name}")
        index_data = IndexData(args.launching_index_name, OUTPUT_PATH)
        index_data.run()
        # When SearchUI index is not hardcoded, it will be use args.launching_index_name
        run_searchui(args.launching_index_name)


def main():
    args, parser = get_parameters()

    set_parameters(args)
    validate_parameters(args, parser)

    if args.version:
        with open(VERSION_PATH, 'r') as version_file:
            version_data = version_file.read()
            version = json.loads(version_data)
            print(f"qa-docs v{version['version']}")

    # Run a sanity check thru tests directory
    elif args.sanity:
        sanity = Sanity(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH))
        qadocs_logger.debug('Running sanity check')
        sanity.run()

    # Parse tests, index the data and visualize it
    else:
        parse_data(args)
        index_and_visualize_data(args)

    if __name__ == '__main__':
        main()
