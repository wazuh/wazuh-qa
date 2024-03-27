# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from pydantic import BaseModel, IPvAnyAddress


class AnsibleInventory(BaseModel):
    ansible_host: str | IPvAnyAddress
    ansible_user: str
    ansible_port: int
    ansible_ssh_private_key_file: str
