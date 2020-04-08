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

    :param str scenario_name: Name of scenario
    :param str hostname: Hostname to extract ossec.log

    :return: list with the relevant lines
    """
    ossec_path = "/opt/fim_test_results/{}/agent_state/{}/ossec.log".format(
        scenario_name,
        hostname
    )
    watch_list = "warning error".split()
    results = []
    with open(ossec_path, "r") as ossec_log:
        for line in ossec_log:
            if any(word in line.lower() for word in watch_list):
                results.append(line)
    return results


def read_verify_json():
    """
    Extract inner dict from result_json.json

    :return: dict with json verifications
    """
    path = "/opt/fim_test_results/result_json.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    assert('alerts_json_verification' in json_dict)
    return json_dict['alerts_json_verification']


def read_verify_elastic():
    """
    Extract inner dict from result_es.json

    :return: dict with elasticsearch verifications
    """
    path = "/opt/fim_test_results/result_es.json"
    with open(path, "r") as f:
        json_dict = json.load(f)
    assert('alerts_elastic_verification' in json_dict)
    return json_dict['alerts_elastic_verification']


def update_scenario(scenario, verification, content, results_dict):
    """
    Update scenario dict with specific content

    :param str scenario: Name of the scenario
    :param str verification: Type of verification
    :param dict content: Content dict with actual data
    :param dict result_dict: Dictionary to clone as result template

    :return: dict cloned from json_dict with current scenario details updated
    """
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
        for event in ["added", "modified", "deleted"]:
            if event in content:
                for hostname, data in content[event]['hosts'].items():
                    del data['missing_paths']  # remove missing paths
                    data['ossec_log'] = get_ossec_log_errors(scenario, hostname)
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
    Summarize a test_dict of one type of verification and dump
    results into results_dict.
    Use prebuilt_dict as a base if provided.

    :param dict test_dict: Dict with test results
    :param str verification: Type of verification
    :param dict prebuilt_dict: A template dict with previous scenarios summarized, if any

    :return: dict with current and previous scenarios summarized
    """
    results_dict = prebuilt_dict or {}
    for k, v in test_dict['scenarios'].items():
        results_dict = update_scenario(k, verification, v, results_dict)
    return results_dict


def final_summarize():
    """
    Summarize both json and elastic reports and create one global dict
    with enough details in case of failed events.

    :return: dict with final summary
    """
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
