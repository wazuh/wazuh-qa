# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms


def sanitize_configuration(configuration):
    """Sanitize the tool configuration.
    """
    for tc_config in configuration:
        for key in tc_config:
            tc_config[key.lower()] = tc_config.pop(key)

    return configuration
