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


def get_ossec_log_errors(scenario_name, hostname):
    """
    Return relevant lines from ossec.log
    """
    ossec_path = "/opt/fim_test_results/{}/agent_state/{}/ossec.log".format(
        scenario_name,
        hostname
    )
    watch_list = "syscheck warning error".split()
    results = []
    with open(ossec_path, "r") as ossec_log:
        for line in ossec_log:
            if any(word in line.lower() for word in watch_list):
                results.append(line)
    return results


def read_verify_json():
    path = "/opt/fim_test_results/result_json.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    assert('alert_json_verification' in json_dict)
    return json_dict['alert_json_verification']


def read_verify_elastic():
    path = "/opt/fim_test_results/result_es.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    assert('alert_elasticsearch_verification' in json_dict)
    return json_dict['alert_elasticsearch_verification']


def update_scenario(scenario, verification, content, results_dict):
    current_dict = copy.deepcopy(results_dict)
    if content['passed']:
        # scenario SUCCESS
        if scenario in current_dict:
            # no need to update scenario results
            return current_dict
        else:
            # create new entry for scenario
            current_dict[scenario] = {'state': 'SUCCESS'}
    else:
        # scenario FAILED
        if scenario in current_dict:
            if current_dict[scenario]['state'] == 'SUCCESS':
                # overwrite with FAILED
                current_dict[scenario]['state'] = 'FAILED'
                current_dict[scenario]['errors'] = {verification: content}
            else:
                # add more FAILED
                current_dict[scenario]['errors'][verification] = content
        else:
            # create new entry with FAILED
            current_dict[scenario] = {'state': 'FAILED'}
            current_dict[scenario]['errors'] = {verification: content}
    return current_dict


def summarize_result(test_dict, verification, prebuilt_dict=None):
    """
    Summarize a test_dict and dump results into results_dict
    Use prebuilt_dict as a base if provided.
    """
    results_dict = prebuilt_dict or {}
    for k, v in test_dict['scenarios'].items():
        results_dict = update_scenario(k, verification, v, results_dict)
    return results_dict


def final_summarize():
    json_dict = read_verify_json()
    elastic_dict = read_verify_elastic()
    json_sum = summarize_result(json_dict, "json")
    final_result = summarize_result(elastic_dict, "elasticsearch", json_sum)
    return final_result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=str, required=False,
                        dest='output_file',
                        default='/opt/fim_test_results/summary.json',
                        help="Output file to save summary")
    args = parser.parse_args()
    out_path = args.output_file
    summarize = final_summarize()
    with open(out_path, "w") as f:
        json.dump(summarize, f)
