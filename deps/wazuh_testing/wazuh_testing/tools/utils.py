# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re


def replace_regex(pattern, new_value, data, replace_group=False):
    """
    Function to replace a pattern string in a data text

    Parameters
    ----------
    pattern: str
        Regular expresion pattern
    new_value: str
        New replaced string
    data: str
        String to search and replace
    replace_group: bool
        Flag to replace a plain expression or to replace it in a group

    Returns
    -------
    str:
        New replaced text
    """
    compiled_pattern = re.compile(pattern, re.DOTALL)
    replace_value = rf"\g<1>{new_value}\g<3>" if replace_group else new_value

    return re.sub(compiled_pattern, replace_value, data)


def insert_xml_tag(pattern, tag, value, data):
    """
    Function to insert a xml tag in a string data.

    Parameters
    ----------
    pattern: str
        regex pattern.
        Important: the regex must be composed of 3 groups. The inserted data will be added between group 1 and group 2.
        Example:
            r'(.*</tag1>)(<my_custom_tag>)(<tag2>)
                </tag1>
                <my_custom_tag>custom_value</my_custom_tag>
                <tag2>
                ...
    tag: str
        new xml tag
    value: str
        value of new xml tag
    data: str
        XML string data

    Returns
    -------
    str:
        new XML string data
    """
    xml_tag = f"\n  <{tag}>{value}</{tag}>"
    compiled_pattern = re.compile(pattern, re.DOTALL)

    return re.sub(compiled_pattern, rf"\g<1>{xml_tag}\n  \g<2>\g<3>", data)
