#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import copy


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
                        line = key5 + ' (' + value5['os'] + ' ' + value5['distribution'] + ')'
                        endpoints_list.append(line)
    return set(endpoints_list)


def set_to_md(agents):
    md_output = ''
    for element in agents:
        md_output += " - " + element + " \n"
    return md_output

def final_summarize():
    json_dict = read_verify_json()
    agents_set = endpoints_set(json_dict)
    md_summary = set_to_md(agents_set)
    return md_summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=str, required=False,
                        dest='output_file',
                        default='/opt/fim_test_results/agents_summary.md',
                        help="Output file to save agents OS summary")
    args = parser.parse_args()
    out_path = args.output_file
    agents_list = final_summarize()
    with open(out_path, "w") as f:
        json.dump(agents_list, f)
