import argparse
import logging
import os

from wazuh_testing.qa_docs.lib.config import Config
from wazuh_testing.qa_docs.lib.index_data import IndexData
from wazuh_testing.qa_docs.lib.sanity import Sanity
from wazuh_testing.qa_docs.doc_generator import DocGenerator

VERSION = '0.1'
CONFIG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'config.yaml')
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'output')
LOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'log')
SEARCH_UI_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'qa_docs', 'search_ui')


def start_logging(folder, debug_level=logging.INFO):
    LOG_PATH = os.path.join(folder, f"{os.path.splitext(os.path.basename(__file__))[0]}.log")
    if not os.path.exists(folder):
        os.makedirs(folder)
    logging.basicConfig(filename=LOG_PATH, level=debug_level)


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

    parser.add_argument('-i', '--index-data', dest='index_name',
                        help="Indexes the data named as you specify as argument to elasticsearch.")

    parser.add_argument('-l', '--launch-ui', dest='launch_app',
                        help="Indexes the data named as you specify as argument and launch SearchUI.")

    parser.add_argument('-T', dest='test_input',
                        help="Parse the test that you pass as argument.")

    parser.add_argument('-o', dest='output_path',
                        help="Specifies the output directory for test parsed when -T is used.")

    parser.add_argument('-I', dest='test_dir', required=True,
                        help="Path where tests are located.")

    parser.add_argument('-e', dest='test_exist',
                        help="Checks if test exists or not",)

    args = parser.parse_args()

    if args.debug_level:
        start_logging(LOG_PATH, logging.DEBUG)
    else:
        start_logging(LOG_PATH)

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
        sanity.run()
    elif args.index_name:
        indexData = IndexData(args.index_name, Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
        indexData.run()
    elif args.launch_app:
        indexData = IndexData(args.launch_app, Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
        indexData.run()
        os.chdir(SEARCH_UI_PATH)
        os.system("ELASTICSEARCH_HOST=http://localhost:9200 npm start")
    else:
        if not args.test_exist:
            docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
            if args.test_input:
                if args.output_path:
                    docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, args.output_path, args.test_input))
                else:
                    docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, '', args.test_input))
            docs.run()

    if __name__ == '__main__':
        main()
