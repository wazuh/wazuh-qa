# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import ipaddress
import json
import logging
import numbers
import re
import socket
import string
from datetime import datetime
from functools import wraps
from random import randint, SystemRandom
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
                    msg = f'Exception: "{exception}". {attempt}/{attempts} remaining attempts. ' \
                          f'Waiting {wait_time} seconds.'
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
    r"""
    Function to insert a xml tag in a string data.

    Args:
        pattern (str): regex pattern. The regex must be composed of 3 groups. The inserted data will be added
            between group 1 and group 2.
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


def replace_in_file(filename, to_replace, replacement):
    """Replaces all occurrences of <to_replace> with <replacement> in <filename> file.
    This helper performs a search and replacement similar to `sed -i` to a desired file.
    """
    with open(filename) as f:
        replace_content = f.read().replace(to_replace, replacement)

    with open(filename, "w") as f:
        f.write(replace_content)


def get_random_ip():
    """Create a random ip address.

    Return:
        String: Random ip address.
    """
    return fr"{randint(0,255)}.{randint(0,255)}.{randint(0,255)}.{randint(0,255)}"


def get_random_port() -> str:
    """Create a port number.

    Return:
        String: Random port number.
    """
    return f"{randint(0, 10000)}"


def get_random_string(string_length, digits=True):
    """Create a random string with specified length.

    Args:
        string_length (int): Random string length.
        digits (boolean): Digits availability for string generation.

    Returns:
        String: Random string.
    """
    character_set = string.ascii_uppercase + string.digits if digits else string.ascii_uppercase

    return ''.join(SystemRandom().choice(character_set) for _ in range(string_length))


def get_version():
    f = open('../../version.json')
    data = json.load(f)
    version = data['version']
    return version


def lower_case_key_dictionary_array(array_dict):
    """Given an array of dictionaries, create a copy of it with the keys of each dictionary in lower case.

    Args:
        array_dict (List): List of dictionaries.

    Returns:
        List: List of dictionaries with lowercase keys.
    """
    return [{str(key).lower(): value for key, value in element.items()} for element in array_dict]


def get_host_name():
    """
    Gets the system host name.

    Returns:
        str: The host name.
    """
    return socket.gethostname()


def validate_interval_format(interval):
    """Validate that the interval passed has the format in which the last digit is a letter from those passed and
       the other characters are between 0-9."""
    if interval == '':
        return False
    if interval[-1] not in ['s', 'm', 'h', 'd', 'w', 'y'] or not isinstance(int(interval[0:-1]), numbers.Number):
        return False
    return True


def format_ipv6_long(ipv6_address):
    """Return the long form of the address representation in uppercase.

    Args:
        ipv6_address (str): IPV6 address

    Returns:
        str: IPV6 long form
    """
    return (ipaddress.ip_address(ipv6_address).exploded).upper()


def get_datetime_diff(phase_datetimes, date_format):
    """Calculate the difference between two datetimes.

    Args:
        phase_datetimes (list): List containing start and end datetimes.
        date_format (str): Expected datetime shape.
    """
    return datetime.strptime(phase_datetimes[1], date_format) - datetime.strptime(phase_datetimes[0], date_format)
