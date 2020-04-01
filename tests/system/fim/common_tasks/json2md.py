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

def read_verify_json():
    path = "/opt/fim_test_results/result_json.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    assert('alerts_json_verification' in json_dict)
    return json_dict['alerts_json_verification']


def endpoints_set(dict):
    endpoints_list = []
    del dict['passed']
    for key1, value1 in dict.items():
        for key2, value2 in value1.items():
            del value2['passed']
            for key3, value3 in value2.items():
                del value3['passed']
                for key4, value4 in value3.items():
                    for key5, value5 in value4.items():
                        line = "{} ({} {})".format(key5,value5['os'],value5['distribution'])
                        endpoints_list.append(line)
    endpoints = "**Agents - OS list:** \n"
    for element in set(endpoints_list):
        endpoints += " - {} \n".format(element)
    return endpoints


def host2markdown(name, jsonObject):
    host_data = ""
    if jsonObject['passed'] == True:
        return " - {} - {} \n".format(name, '[✓]')
    else:
        host_data = " - {} - {} \n".format(name, '[ERROR]')
        host_data += "``` \n"
        for key, value in jsonObject.items():
            host_data += "    - {} : {} \n".format(key, str(value))
        host_data += "``` \n"
    return host_data

def event2markdown(event, hosts, passed):
    result=''
    if passed == True:
        result = "**Event: {} - {}**\n".format(event, '[✓]')
        return result
    else:
        result = "**Event: {} - {}**\n".format(event, '[ERROR]')
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
        if verification == 'elasticsearch':
            result += "### {}".format('Verify elasticsearch')
        else:
            result += "### {}".format('Verify `alerts.json`')
        if test_results['passed'] == True:
            result += " - [✓] \n"
        else:
            result += " - [ERROR] \n"
            del test_results['passed']
            for event, event_content in test_results.items():
                result += event2markdown(event, event_content['hosts'], event_content['passed']) + "\n"
    return result + "***\n"


def json2markdown(summary_json, verify_json):
    result = ""
    result += endpoints_set(verify_json) + "\n"
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
    verify_json = read_verify_json()
    printable_summary = json2markdown(summary_json,verify_json)
    with open(out_path, "w") as f:
        f.write(printable_summary)
