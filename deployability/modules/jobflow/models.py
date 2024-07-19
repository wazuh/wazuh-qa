# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path
from typing import Literal
from pydantic import BaseModel


class InputPayload(BaseModel):
    jobflow_file: str | Path
    threads: int = 1
    dry_run: bool = False
    log_level: Literal['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] = 'INFO'
    schema_file: str | Path | None = None
