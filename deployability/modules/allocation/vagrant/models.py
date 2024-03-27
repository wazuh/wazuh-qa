# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from pathlib import Path
from pydantic import field_validator

from modules.allocation.generic.models import ProviderConfig
from .utils import VagrantUtils


class VagrantConfig(ProviderConfig):
    ip: str
    cpu: int
    memory: int
    box: str
    box_version: str
    private_key: str
    public_key: str
    name: str
    port: int = None
    platform: str
    arch: str

    @field_validator('public_key', mode='before')
    @classmethod
    def check_public_key(cls, v: str) -> str:
        path = Path(v)
        if not path.exists() or not path.is_file():
            cmd = 'stat ' + str(path)
            if not VagrantUtils.remote_command(cmd):
                raise ValueError(f"Invalid public key path: {path}")
        return v
