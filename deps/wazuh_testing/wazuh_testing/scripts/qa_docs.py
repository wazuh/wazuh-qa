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
    LOG_PATH = os.path.join(folder, os.path.splitext(os.path.basename(__file__))[0]+".log")
    if not os.path.exists(folder):
        os.makedirs(folder)
    logging.basicConfig(filename=LOG_PATH, level=debug_level)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help="Run a sanity check", action='store_true', dest='sanity')
    parser.add_argument('-v', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-d', help="Enable debug messages.", action='count', dest='debug_level')
    parser.add_argument('-i', help="Indexes the data to elasticsearch.", dest='index_name')
    parser.add_argument('-l', help="Indexes the data and launch the application.", dest='launch_app')
    parser.add_argument('-T', help="Test name or path to parse.", dest='test_input')
    parser.add_argument('-o', help="Output directory path.", dest='output_path')
    parser.add_argument('-I', help="Tests input directory", dest='test_dir', required=True)
    args = parser.parse_args()

    if args.debug_level:
        start_logging(LOG_PATH, logging.DEBUG)
    else:
        start_logging(LOG_PATH)

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
        docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, OUTPUT_PATH))
        if args.test_input:
            if args.output_path:
                docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, args.output_path, args.test_input))
            else:
                docs = DocGenerator(Config(CONFIG_PATH, args.test_dir, '', args.test_input))
        docs.run()

    if __name__ == '__main__':
        main()