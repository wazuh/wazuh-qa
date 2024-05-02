# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from modules.allocation.generic.models import ProviderConfig


class AWSConfig(ProviderConfig):
    ami: str
    zone: str
    user: str
    key_name: str
    type: str
    storage: int
    security_groups: list[str]
    termination_date: str
    issue: str | None = None
    team: str
    name: str
    host_identifier: str | None = None
    platform: str
