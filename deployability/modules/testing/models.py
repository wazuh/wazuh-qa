from pathlib import Path
from pydantic import BaseModel, field_validator, model_validator
from typing import Literal, Dict

class ExtraVars(BaseModel):
    """Extra vars for testing module."""
    component: Literal['manager', 'agent']
    dependencies: list[str]
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str | None = None
    working_dir: str = '/tmp/tests'

class InputPayload(ExtraVars):
    """Input payload for testing module."""
    tests: list[str]
    inventory: Path
    dependencies: list[str]
    cleanup: bool = True

    @field_validator('tests', mode='before')
    def validate_tests(cls, value) -> list[str]:
        """Validate tests names."""
        if type(value) is str:
            value = value.split(',')
        return value

    def validate_inventory(cls, value) -> Path:
        """Validate inventory path."""
        if not Path(value).exists():
            raise ValueError(f'Inventory file "{value}" does not exist')
        return Path(value)

    @model_validator(mode='before')
    def validate_dependencies(cls, values) -> dict:
        """Validate required fields."""
        if isinstance(values['dependencies'], str):
            values['dependencies'] = values['dependencies'].split(',')
        if values.get('component') == 'agent' and not values.get('dependencies'):
            raise ValueError('dependencies are required when component is agent')
        return values
