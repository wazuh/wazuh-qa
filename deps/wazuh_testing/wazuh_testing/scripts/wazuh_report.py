# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import argparse
import json

from wazuh_testing.tools.sources.report_generator import ReportGenerator


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]", description='Wazuh data sources generator',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--path', dest='artifact_path', default=None,
                        help='Artifact path.', action='store')

    parser.add_argument('-r', '--report', dest='report_path', default='report.json',
                        help='Report path.', action='store')
    return parser.parse_args()


def main():
    options = get_script_arguments()
    parser = ReportGenerator(options.artifact_path)

    json_report = parser.make_report()

    with open(f"{options.report_path}", 'w') as report:
        report.write(json.dumps(json_report, sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
