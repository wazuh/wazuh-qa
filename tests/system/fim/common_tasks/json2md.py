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


def read_summary_json():
    path = "../provisioning/agents_status/fim_test_results/summary.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    return json_dict

def host2markdown(name, jsonObject):
    line = '#### ' + name + '\n'
    for key in jsonObject:
        value = jsonObject[key]
        line += ' - ' + key + ': ' + str(value) + '\n'
    return repr(line)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=str, required=False,
                        dest='output_file',
                        default='./printable_summary.md',
                        help="Output file to save the printable summary")
    args = parser.parse_args()
    out_path = args.output_file
    printable_summary = read_summary_json()
    with open(out_path, "w") as f:
        json.dump(printable_summary, f)
