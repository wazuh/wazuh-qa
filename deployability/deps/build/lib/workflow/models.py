from pathlib import Path
from typing import Literal
from pydantic import BaseModel


class InputPayload(BaseModel):
    workflow_file: str | Path
    threads: int = 1
    dry_run: bool = False
    log_level: Literal['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] = 'INFO'
    schema_file: str | Path | None = None
