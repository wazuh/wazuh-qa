# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import sys
import json
import git

from datetime import datetime
from elasticsearch import Elasticsearch
from tempfile import gettempdir

from wazuh_testing.qa_docs.lib.config import Config
from wazuh_testing.qa_docs.lib.index_data import IndexData
from wazuh_testing.qa_docs.lib.sanity import Sanity
from wazuh_testing.qa_docs.lib import utils
from wazuh_testing.qa_docs.doc_generator import DocGenerator
from wazuh_testing.qa_docs import QADOCS_LOGGER
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.exceptions import QAValueError

VERSION_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'VERSION.json')
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'qa_docs', 'schema.yaml')
OUTPUT_PATH = os.path.join(gettempdir(), 'qa_docs', 'output')
OUTPUT_FORMAT = 'json'
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
    """Set the QADOCS parameters.

    Args:
        args (argparse.Namespace): The parameters that the tool receives.
    """
    # Set the qa-docs logger level
    if args.debug_level:
        set_qadocs_logger_level('DEBUG')

    if args.logging_level:
        set_qadocs_logger_level(args.logging_level)

    # Deactivate the qa-docs logger if necessary.
    if args.no_logging:
        set_qadocs_logger_level(None)

    if args.output_path:
        global OUTPUT_PATH
        OUTPUT_PATH = os.path.join(args.output_path, 'output')

    if args.run_with_docker:
        OUTPUT_PATH = args.output_path if args.output_path else os.path.join(gettempdir(), 'qa_docs')


def get_parameters():
    """Capture the script parameters

    Returns:
        argparse.Namespace: Object with the script parameters.
        argparse.ArgumentParser: Object with from the parser class.
    """
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    parser.add_argument('--sanity-check', action='store_true', dest='sanity',
                        help="Run a sanity check.")

    parser.add_argument('--no-logging', action='store_true', dest='no_logging',
                        help="Do not perform logging when running the tool.")

    parser.add_argument('-v', '--version', action='store_true', dest="version",
                        help="Print qa-docs version.")

    parser.add_argument('-d', '--debug', action='count', dest='debug_level',
                        help="Enable debug messages.")

    parser.add_argument('-p', '--tests-path', dest='tests_path',
                        help="Path where tests are located.")

    parser.add_argument('-t', '--types', nargs='+', default=[], dest='test_types',
                        help="Parse the tests from type(s) that you pass as argument.")

    parser.add_argument('-c', '--components', nargs='+', default=[], dest='test_components',
                        help="Parse the tests from components(s) that you pass as argument.")

    parser.add_argument('-s', '--suites', nargs='+', default=[], dest='test_suites',
                        help="Parse the tests from suite(s) that you pass as argument.")

    parser.add_argument('-m', '--modules', nargs='+', default=[], dest='test_modules',
                        help="Parse the test(s) that you pass as argument.")

    parser.add_argument('-i', '--index-data', dest='index_name',
                        help="Indexes the data named as you specify as argument to elasticsearch.")

    parser.add_argument('-l', '--launch-ui', dest='app_index_name',
                        help="Launch SearchUI using the index that you specify.")

    parser.add_argument('-il', dest='launching_index_name',
                        help="Indexes the data named as you specify as argument and launch SearchUI.")

    parser.add_argument('-o', dest='output_path',
                        help="Specifies the output directory for test parsed when `-t, --tests` is used.")

    parser.add_argument('--format', dest='output_format', choices=['json', 'yaml'],
                        help="Specifies the generated files format.")

    parser.add_argument('-e', '--exist', nargs='+', default=[], dest='test_exist',
                        help="Checks if test(s) exist or not.",)

    parser.add_argument('--validate-parameters', action='store_true', dest='validate_parameters',
                        help='Validate the parameters passed to the qa-docs tool.')

    parser.add_argument('--docker-run', action='store_true', dest='run_with_docker',
                        help='Run qa-docs using within a docker container')

    parser.add_argument('--qa-branch', dest='qa_branch',
                        help='Specifies the qa branch that will be used as input for the tests to be parsed.')

    parser.add_argument('--check-documentation', action='store_true', dest='check_doc',
                        help="Checks if test(s) are correctly documentated according to qa-docs current schema.",)

    parser.add_argument('--logging-level', dest='logging_level',
                        help="Set the logging level.",)

    return parser.parse_args(), parser


def check_incompatible_parameters(parameters):
    """Check the parameters that qa-docs receives and check any incompatibilities.

    Args:
        parameters (argparse.Namespace): The parameters that the tool receives.
    """
    default_run = parameters.test_types or parameters.test_components or parameters.test_suites or \
        parameters.test_modules
    api_run = parameters.index_name or parameters.app_index_name or parameters.launching_index_name
    test_run = parameters.test_exist

    qadocs_logger.debug('Checking parameters incompatibilities.')

    if parameters.version and (default_run or api_run or parameters.tests_path or test_run):
        raise QAValueError('The -v(--version) option must be run in isolation.',
                           qadocs_logger.error)

    if parameters.sanity:
        if default_run or api_run or test_run:
            raise QAValueError('The -s, --sanity-check option must be run only with the -I(--tests-path) option.',
                               qadocs_logger.error)

        if parameters.tests_path is None:
            raise QAValueError('The -s(--sanity-check) option needs the path to the tests to be parsed. You must '
                               'specify it by using --tests-path',
                               qadocs_logger.error)

    if parameters.test_types:
        if parameters.tests_path is None and not parameters.run_with_docker:
            raise QAValueError('The --types option needs the path to the tests to be parsed. You must specify it by '
                               'using --tests-path',
                               qadocs_logger.error)

    if parameters.test_components:
        if parameters.tests_path is None and not parameters.run_with_docker:
            raise QAValueError('The --components option needs the path to the tests to be parsed. You must specify it '
                               'by using --tests-path',
                               qadocs_logger.error)

    if parameters.test_suites:
        if not parameters.test_components:
            raise QAValueError('The --suites option needs the suite module to be parsed. You must specify it '
                               'using --components',
                               qadocs_logger.error)

    if parameters.test_modules:
        if parameters.tests_path is None and not parameters.run_with_docker:
            raise QAValueError('The -m(--modules) option needs the path to the tests to be parsed. You must specify it '
                               'using --tests-path',
                               qadocs_logger.error)

        if parameters.index_name:
            raise QAValueError('The -m(--modules) option is not compatible with -i option',
                               qadocs_logger.error)

        if parameters.app_index_name:
            raise QAValueError('The -m(--modules) option is not compatible with -l option',
                               qadocs_logger.error)

        if parameters.launching_index_name:
            raise QAValueError('The -m(--modules) option is not compatible with -il option',
                               qadocs_logger.error)

    if parameters.test_exist:
        if parameters.tests_path is None:
            raise QAValueError('The -e(--exist) option needs the path to the tests to be parsed. You must specify it by'
                               ' using -I, --tests-path',
                               qadocs_logger.error)

        if parameters.index_name:
            raise QAValueError('The -e(--exist) option is not compatible with -i option',
                               qadocs_logger.error)

        if parameters.app_index_name:
            raise QAValueError('The -e(--exist) option is not compatible with -l option',
                               qadocs_logger.error)

        if parameters.launching_index_name:
            raise QAValueError('The -e(--exist) option is not compatible with -il option',
                               qadocs_logger.error)

    if parameters.output_path:
        if parameters.app_index_name:
            raise QAValueError('The -o option is not compatible with -l option',
                               qadocs_logger.error)

        if parameters.test_exist:
            raise QAValueError('The -o option is not compatible with -e option',
                               qadocs_logger.error)

    if parameters.no_logging and parameters.debug_level:
        raise QAValueError('You cannot specify debug level and no-logging at the same time.',
                           qadocs_logger.error)

    if parameters.logging_level:
        if parameters.no_logging:
            raise QAValueError('You cannot run qa-docs in no-logging mode and set a logging level.',
                               qadocs_logger.error)

        if parameters.debug_level:
            raise QAValueError('You cannot run qa-docs in debug mode and set a logging level.',
                               qadocs_logger.error)

    if parameters.run_with_docker:
        if not parameters.qa_branch:
            raise QAValueError('The docker container run needs a QA branch with the tests input.',
                               qadocs_logger.error)

    if parameters.qa_branch:
        if not parameters.run_with_docker:
            raise QAValueError('If you want to use a QA branch as input you need to specify the --docker-run option. '
                               'In the future, with --qa-branch It will also use the tests within the branch in local '
                               'as input',
                               qadocs_logger.error)

    if parameters.check_doc:
        if not parameters.test_modules:
            raise QAValueError('The --check-documentation option needs the modules to be checked. You must specify it '
                               'by  using -m.', qadocs_logger.error)

    qadocs_logger.debug('Parameters incompatibilities checked.')


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

    if parameters.run_with_docker:
        branches = git.Git().branch("--all").split()
        if f"remotes/origin/{parameters.qa_branch}" not in branches:
            raise QAValueError(f"{parameters.qa_branch} not found in Wazuh-QA repo.",
                               qadocs_logger.error)
    else:
        # Check if the directory where the tests are located exist
        if parameters.tests_path:
            if not os.path.exists(parameters.tests_path):
                raise QAValueError(f"{parameters.tests_path} does not exist. Tests directory not found.",
                                   qadocs_logger.error)

        # Check that the index exists
        if parameters.app_index_name:
            es = Elasticsearch()
            try:
                es.count(index=parameters.app_index_name)
            except Exception as index_exception:
                raise QAValueError(f"Index exception: {index_exception}", qadocs_logger.error)

        if parameters.test_types:
            for type in parameters.test_types:
                if type not in os.listdir(parameters.tests_path):
                    raise QAValueError(f"The given type: {type} has not been found in {parameters.tests_path}",
                                       qadocs_logger.error)

        # Check that components selection is done within a test type
        if parameters.test_components:
            if len(parameters.test_types) != 1:
                raise QAValueError('The --components option works when is only parsing a single test type. Use --types '
                                   'with just one type if you want to parse some components within a test type.',
                                   qadocs_logger.error)

            if parameters.test_suites:
                if len(parameters.test_components) != 1:
                    raise QAValueError('The --suites option works when is only parsing a single test module. Use '
                                       '--components with just one type if you want to parse some components within a '
                                       'test type.', qadocs_logger.error)

        if parameters.test_modules or parameters.test_exist:
            # If at least one module is specified
            if len(parameters.test_components) != 1:
                raise QAValueError('The --modules option works when is only parsing a single test component. Use '
                                   '--components with just one component if you want to parse some modules within a '
                                   'test component.', qadocs_logger.error)

            if parameters.test_suites:
                if len(parameters.test_suites) != 1:
                    raise QAValueError('The --modules option works when is only parsing a single test suite. Use '
                                       '--suites with just one type if you want to parse some modules within a '
                                       'test suite.', qadocs_logger.error)

            for component in parameters.test_components:
                type_path = os.path.join(parameters.tests_path, parameters.test_types[0])
                component_path = os.path.join(type_path, component)
                if component not in os.listdir(type_path):
                    raise QAValueError(f"The given component: {component} has not been found in {type_path}",
                                       qadocs_logger.error)

                for suite in parameters.test_suites:
                    if suite not in os.listdir(component_path):
                        raise QAValueError(f"The given suite: {suite} has not been found in {component_path}",
                                           qadocs_logger.error)

        if parameters.test_modules:
            suite_path = '' if not parameters.test_suites else parameters.test_suites[0]

            for module in parameters.test_modules:
                suite_path = os.path.join(component_path, suite_path)
                module_file = f"{module}.py"
                if module_file not in os.listdir(suite_path):
                    if utils.get_file_path_recursively(module_file, suite_path) is None:
                        raise QAValueError(f"The given module: {module_file} has not been found in {suite_path}",
                                           qadocs_logger.error)

    qadocs_logger.debug('Input parameters validation completed')


def install_searchui_deps():
    """Install SearchUI dependencies if needed"""
    os.chdir(SEARCH_UI_PATH)
    if not os.path.exists(os.path.join(SEARCH_UI_PATH, 'node_components')):
        qadocs_logger.info('Installing SearchUI dependencies')
        utils.run_local_command("npm install")


def run_searchui(index):
    """Run SearchUI installing its dependencies if necessary"""
    install_searchui_deps()
    qadocs_logger.debug('Running SearchUI')

    utils.run_local_command(f"npm --ELASTICHOST=http://localhost:9200 --INDEX={index} start")


def parse_data(args):
    """Parse the tests and collect the data."""
    if args.test_exist:

        if args.test_suites:

            # Looking for specified modules
            doc_check = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                            args.test_components, args.test_suites, args.test_exist),
                                     OUTPUT_FORMAT)
        else:

            # Parse specified components
            doc_check = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                            args.test_components, test_modules=args.test_exist), OUTPUT_FORMAT)

        doc_check.check_module_exists(args.tests_path)

    # Parse a list of test types
    elif args.test_types:
        qadocs_logger.info(f"Parsing the following test(s) type(s): {args.test_types}")

        # Parse a list of test components
        if args.test_components:
            qadocs_logger.info(f"Parsing the following test(s) components(s): {args.test_components}")

            if args.test_suites:
                qadocs_logger.info(f"Parsing the following suite(s): {args.test_suites}")

                if args.test_modules:
                    qadocs_logger.info(f"Parsing the following modules(s): {args.test_modules}")

                    # Parse specified modules
                    docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                               args.test_components, args.test_suites, args.test_modules),
                                        OUTPUT_FORMAT)
                else:
                    # Parse specified suites
                    docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                        args.test_components, args.test_suites), OUTPUT_FORMAT)
            else:
                if args.test_modules:
                    qadocs_logger.info(f"Parsing the following modules(s): {args.test_modules}")
                    test_modules_values = args.test_modules
                else:
                    test_modules_values = None

                # Parse specified components
                docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types,
                                           args.test_components, test_modules=test_modules_values), OUTPUT_FORMAT)

        else:
            # Parse all type of tests
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH, args.test_types), OUTPUT_FORMAT)

    # Parse the whole path
    else:
        if not (args.index_name or args.app_index_name or args.launching_index_name):
            qadocs_logger.info(f"Parsing all tests located in {args.tests_path}")
            docs = DocGenerator(Config(SCHEMA_PATH, args.tests_path, OUTPUT_PATH), OUTPUT_FORMAT)
            docs.run()

    if (args.test_types or args.test_components or args.test_modules) and not (args.check_doc or args.test_exist):
        qadocs_logger.info('Running QADOCS')
        docs.run()
    elif args.test_modules and args.check_doc:
        docs.check_documentation()


def index_and_visualize_data(args):
    """Index the data previously parsed and visualize it."""
    # Index the previous parsed tests into Elasticsearch
    if args.index_name:
        index_data = IndexData(args.index_name, OUTPUT_PATH, OUTPUT_FORMAT)
        index_data.run()

    # Launch SearchUI with index_name as input
    elif args.app_index_name:
        # When SearchUI index is not hardcoded, it will be use args.app_index_name
        run_searchui(args.app_index_name)

    # Index the previous parsed tests into Elasticsearch and then launch SearchUI
    elif args.launching_index_name:
        qadocs_logger.debug(f"Indexing {args.launching_index_name}")
        index_data = IndexData(args.launching_index_name, OUTPUT_PATH, OUTPUT_FORMAT)
        index_data.run()
        # When SearchUI index is not hardcoded, it will be use args.launching_index_name
        run_searchui(args.launching_index_name)


def main():
    args, parser = get_parameters()

    set_parameters(args)
    validate_parameters(args, parser)
    if args.validate_parameters:
        return 0

    if args.run_with_docker:
        command = utils.get_qa_docs_run_options(args)
        qadocs_logger.info(f"Running {command} in a docker container.")
        utils.qa_docs_docker_run(args.qa_branch, command, OUTPUT_PATH)
    elif args.version:
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
