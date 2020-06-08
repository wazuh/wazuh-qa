# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json
import re


def replace_regex_group(pattern, new_value, data):
    """
    Replace a grouped text string with a regex, with a new one.

    Parameters
    ----------
    pattern: str
        Regex pattern, for instance: r"CVE:(),"
    new_value: str
        String to replace the grouped text
    data: str
        String data

    Returns
    -------
    data: str
        Data string with the new changes made
    """
    match = re.search(pattern, data)

    if match is not None:
        try:
            string_matched = match.group(0)
            string_to_replace = match.group(1)
            new_string = string_matched.replace(string_to_replace, new_value)
            data = re.sub(pattern, new_string, data)
        except IndexError:
            pass

    return data
