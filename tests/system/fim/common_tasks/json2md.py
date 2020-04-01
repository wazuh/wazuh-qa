#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json


def read_summary_json():
    path = "/opt/fim_test_results/summary.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    return json_dict


def host2markdown(name, jsonObject):
    line = "#### {} \n".format(name)
    for key, value in jsonObject.items():
        line += " - {} : {} \n".format(key, str(value))
    return line


def event2markdown(event, hosts):
    result = "**Event: {}**\n".format(event)
    for host, json_dict in hosts.items():
        result += host2markdown(host, json_dict)
    return result


def scenario2markdown(scenario_name, scenario_content):
    """
    Convert a scenario to markdown syntax
    """
    if scenario_content['state'] == 'SUCCESS':
        return "### {} :heavy_check_mark:\n***\n".format(scenario_name)
    result = "### {} :x:\n".format(scenario_name)
    for verification, test_results in scenario_content['errors'].items():
        result += "### {}\n".format(verification)
        del test_results['passed']
        for event, event_content in test_results.items():
            result += event2markdown(event, event_content['hosts'])
    return result + "***\n"


def json2markdown(summary_json):
    result = ""
    for scenario, content in summary_json.items():
        result += scenario2markdown(scenario, content)
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=str, required=False,
                        dest="output_file",
                        default="./printable_summary.md",
                        help="Output file to save the printable summary")
    args = parser.parse_args()
    out_path = args.output_file
    summary_json = read_summary_json()
    printable_summary = json2markdown(summary_json)
    with open(out_path, "w") as f:
        f.write(printable_summary)
