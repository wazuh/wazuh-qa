# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import logging
import re
from functools import wraps
from time import sleep


def retry(exceptions, attempts=5, delay=1, delay_multiplier=2):
    """Decorator used to retry functions.

    This function will execute `func` multiple times until the max number of attempts is reached or
    the function is executed without errors.

    Args:
        exceptions (Exception or tuple): which exceptions to catch.
        attempts (int): number of times to retry the execution of func before abort.
        delay (int): number of seconds to wait between successive attempts.
        delay_multiplier (int): factor to multiply the wait time on each attempt.

    Example:
        @retry(requests.exceptions.Timeout, attempts=10, delay=5, backoff=0)
        def send_message(msg, dest):
    """
    def retry_function(func):
        wraps(func)

        def to_retry(*args, **kwargs):
            attempt, wait_time, wait_multiplier, excepts = attempts, delay, delay_multiplier, exceptions
            while attempt > 0:
                try:
                    return func(*args, **kwargs)
                except excepts as exception:
                    wait_time *= wait_multiplier
                    attempt -= 1
                    msg = f'Exception: "{exception}" caught. {attempt}/{attempts}. Retrying after {wait_time} seconds.'
                    logging.warning(msg)
                    sleep(wait_time)
            return func(*args, **kwargs)  # final attempt
        return to_retry  # actual decorator
    return retry_function


def replace_regex(pattern, new_value, data, replace_group=False):
    """
    Function to replace a pattern string in a data text

    Args:
        pattern (str): Regular expresion pattern
        new_value (str): New replaced string
        data (str): String to search and replace
        replace_group (bool): Flag to replace a plain expression or to replace it in a group

    Returns:
        str: New replaced text
    """
    compiled_pattern = re.compile(pattern, re.DOTALL)
    replace_value = rf"\g<1>{new_value}\g<3>" if replace_group else new_value

    return re.sub(compiled_pattern, replace_value, data)


def insert_xml_tag(pattern, tag, value, data):
    """
    Function to insert a xml tag in a string data.

    Args:
        pattern (str): regex pattern. The regex must be composed of 3 groups. The inserted data will be added between group 1 and group 2.
            Example:
                r'(.*\</tag1\>)(\<my_custom_tag\>)(\<tag2\>)
                    \</tag1\>
                    \<my_custom_tag\>custom_value\</my_custom_tag\>
                    \<tag2\>
                    ...
        tag (str): new xml tag
        value (str): value of new xml tag
        data (str): XML string data
    
    Returns:
        str: new XML string data
    """
    xml_tag = f"\n  <{tag}>{value}</{tag}>"
    compiled_pattern = re.compile(pattern, re.DOTALL)

    return re.sub(compiled_pattern, rf"\g<1>{xml_tag}\n  \g<2>\g<3>", data)
