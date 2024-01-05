from pathlib import Path
from typing import Literal
from pydantic import BaseModel, root_validator, validator


class InputPayload(BaseModel):
    """Input payload for testing module."""

    tests: list[str]
    inventory: Path
    component: Literal['manager', 'agent']
    manager_ip: str | None = None
    cleanup: bool = True
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str | None = None

    @validator('inventory', mode='before')
    def validate_inventory(cls, value) -> Path:
        """Validate inventory path."""
        if not Path(value).exists():
            raise ValueError(f'Inventory file "{value}" does not exist')
        return Path(value)

    @root_validator()
    def validate_required_fields(cls, values) -> dict:
        """Validate required fields."""
        if values.get('component') == 'agent' and not values.get('manager_ip'):
            raise ValueError('manager_ip is required when component is agent')
        return values


class ExtraVars(BaseModel):
    """Extra vars for testing module."""
    manager_ip: str = None
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str = None
    ansible_stdout_callback: str = 'yaml'
