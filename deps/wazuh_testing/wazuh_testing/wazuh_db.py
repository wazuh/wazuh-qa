# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def callback_fim_query(line):
    return line


def callback_wazuhdb_response(item):
    if isinstance(item, tuple):
        data, response = item
        return response.decode()
