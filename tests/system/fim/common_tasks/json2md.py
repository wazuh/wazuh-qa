#!/usr/bin/env python3

# Copyright (C) 2015-2020, Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import re

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

def scenario_switcher(scenario):
    switcher = {
                "201_default_configuration_frequency": '[201](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#201---default-syscheck-configuration-linuxwindows-480) - Default syscheck configuration',
                "202_realtime_monitoring": '[202](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#202---real-time-monitoring---add-linuxwindows-531) - Real time monitoring',
                "203_whodata_frequency": '[203](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#203---whodata-linuxwindows-528) - Whodata',
                "204_whodata_linux_noaudit": '[204](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#204---whodata-linux---no-audit-installed-520) - Whodata (no audit)',
                "205_restrict_option": '[205](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#205---use-of-restrict-option-linuxwindows-526) - Restrict option',
                "206_tag_option": '[206](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#206---use-of-tags-linuxwindows-524) - Tags usage',
                "207_report_changes_frequency": '[207](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#207---use-of--report-changes-linuxwindows-523) - Report changes',
                "208_ignore_files": '[208](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#208---use-of-ignore-files-linuxwindows-538) - Ignore files',
                "209_recursion_level": '[209](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#209---recursion-level-540) - Recursion level',
                "210_scheduled_scan": '[210](https://github.com/wazuh/wazuh-qa/wiki/FIM-System-tests:-Scenarios-list#210---scheduled-scan-553) - Scheduled scan'
    }
    return switcher.get(scenario,scenario)

# def scenarioslist(summary_json):
#     scenarioslist = "**Scenarios summary:** \n"
#     for scenario, content in summary_json.items():
#         if content['state'] == 'SUCCESS':
#             scenarioslist += "- {} - {} \n".format(scenario_switcher(scenario),'[✓]')
#         else:
#             scenarioslist += "- {} - {} \n".format(scenario_switcher(scenario),'[ERROR]')
#     return scenarioslist

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
    endpoints = "### Agents - OS list: \n"
    for element in sorted(set(endpoints_list)):
        endpoints += " - {} \n".format(element)
    return endpoints


def host2markdown(name, jsonObject):
    host_data = ""
    if jsonObject['passed'] == True:
        return "    * {} - {} \n".format(name, '[✓]')
    else:
        host_data = "    * {} - {} \n".format(name, '[ERROR]')
        host_data += "    ``` \n"
        for key, value in jsonObject.items():
            host_data += "    - {} : {} \n".format(key, str(value))
        host_data += "    ``` \n"
    return host_data

def event2markdown(event, hosts, passed):
    result=''
    if passed == True:
        result = '\n  * **Event {} - {}**\n'.format(event, '[✓]')
        return result
    else:
        result = '\n  * **Event {} - {}**\n'.format(event, '[ERROR]')
        for host, json_dict in hosts.items():
            result += host2markdown(host, json_dict)
        return result


def scenario2markdown(scenario_name, scenario_content):
    """
    Convert a scenario to markdown syntax
    """
    result = ""
    if scenario_content['state'] == 'SUCCESS':
        result += "### {} :heavy_check_mark:\n".format(scenario_switcher(scenario_name),'[✓]')
        result += "<details><summary><i>Advanced details</i></summary>\n<br>\n"
        result += "\n\nApplicable Syscheck configuration: \n  ```xml \n {} \n ``` \n".format(get_config(scenario_name))
        return result + "\n</details> \n "
    result += "\n### {} :x:\n".format(scenario_switcher(scenario_name),'[ERROR]')
    result += "<details><summary><i>Advanced details</i></summary>\n<br>\n"
    result += "\n\nApplicable Syscheck configuration: \n  ```xml \n {} \n ``` \n".format(get_config(scenario_name))
    for verification, test_results in scenario_content['errors'].items():
        if verification == 'elasticsearch':
            result += "#### - {}".format('Elasticsearch alerts verification')
        else:
            result += "#### - {}".format('alerts.json alerts  verification')
        if test_results['passed'] == True:
            result += " - [✓] \n"
        else:
            result += " - [ERROR] \n"
            del test_results['passed']
            for event, event_content in test_results.items():
                result += event2markdown(event, event_content['hosts'], event_content['passed']) + "\n"
    return result + "\n</details> \n "

def get_config(scenario_name):
    config =""
    with open('/opt/fim_test_results/'+ scenario_name + '/agent_state/Centos_00/ossec.conf', 'r') as f:
        lines = f.readlines()
        syscheck_section = False
        for line in lines:
            if re.search(r'<syscheck>', line):
                if syscheck_section == False:
                    syscheck_section = True
                else:
                    syscheck_section = False
            if syscheck_section == True:
                if re.search(r'frequency', line):
                    config += line
                if re.search(r'fim_testing', line):
                    config += line
                if scenario_name == '208_ignore_files':
                    if re.search(r'mp3', line):
                        config += line
    return config

def json2markdown(summary_json, verify_json):
    result = ""
    result += endpoints_set(verify_json) + "\n"
    result += "***" + "\n"
    result += "### Scenarios report: \n"
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
