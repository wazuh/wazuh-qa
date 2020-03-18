#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


def get_ossec_log_errors(scenario_name, hostname):
    ossec_path = "/opt/fim_tests_results/{}/agent_state/{}/ossec.log".format(scenario_name, hostname)
    watch_list = "syscheck warning error".split()
    results = []
    with open(ossec_path, "r") as ossec_log:
        for line in ossec_log:
            if any(word in line.lower() for word in watch_list):
                results.append(line)
    return results



