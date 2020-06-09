# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def generateString(stringLength=10, character='0'):
    """Generate a string with line breaks.

    Parameters
    ----------
    stringLength : int
        Number of characters to add in the string.
    character : str
         Character to be added.

    Returns
    -------
    random_str : str
        String with line breaks.
    """
    random_str = ''

    for i in range(stringLength):
        random_str += character

        if i % 127 == 0:
            random_str += '\n'

    return random_str
