from pathlib import Path
from typing import Literal
from pydantic import BaseModel, field_validator, model_validator, root_validator, validator


class InputPayload(BaseModel):
    """Input payload for testing module."""

    tests: list[str]
    inventory: Path
    component: Literal['manager', 'agent']
    dependency: Path = None
    cleanup: bool = True
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str | None = None

    @field_validator('tests', mode='before')
    def validate_tests(cls, value) -> list[str]:
        """Validate tests names."""
        if type(value) is str:
            value = value.split(',')
        return value

    @field_validator('inventory', mode='before')
    def validate_inventory(cls, value) -> Path:
        """Validate inventory path."""
        if not Path(value).exists():
            raise ValueError(f'Inventory file "{value}" does not exist')
        return Path(value)

    @model_validator(mode='before')
    def validate_dependency(cls, values) -> dict:
        """Validate required fields."""
        if values.get('component') == 'agent' and not values.get('dependency'):
            raise ValueError('dependency is required when component is agent')
        return values


class ExtraVars(BaseModel):
    """Extra vars for testing module."""
    dependency: str | Path|  None = None
    component: Literal['manager', 'agent']
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str | None = None
    ansible_stdout_callback: str = 'yaml'
