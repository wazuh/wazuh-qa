# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

def compose_settings(__type="", __level="", __predicate="", __is_sierra=False):

    settings_str = ""

    if (__is_sierra):
        settings_str = "/usr/bin/script -q /dev/null "
    
    settings_str = settings_str + "/usr/bin/log stream --style syslog "

    if (__type):
        __type = __type.replace(" ", "")
        for t in __type.split(","):
            settings_str = settings_str + "--type " + t + " "

    if (__level):
        __level = __level.replace(" ", "")
        settings_str = settings_str + "--level " + __level + " "

    if(__predicate):
        settings_str = settings_str + "--predicate " + __predicate

    return settings_str
