from pathlib import Path
from pydantic import BaseModel, field_validator, model_validator
from typing import Literal


class ExtraVars(BaseModel):
    """Extra vars for testing module."""
    component: Literal['manager', 'agent']
    wazuh_version: str
    wazuh_revision: str
    wazuh_branch: str | None = None
    working_dir: str = '/tmp/tests'

class InputPayload(ExtraVars):
    """Input payload for testing module."""
    tests: list[str]
    targets: list[str]
    dependencies: list[str]
    cleanup: bool = True


    @field_validator('tests', mode='before')
    def validate_tests(cls, value) -> list[str]:
        """Validate tests names."""
        if type(value) is str:
            value = value.split(',')

        return value

    @field_validator('targets', mode='before')
    def validate_targets(cls, values) -> list:
        """Validate required fields."""

        return values

    @model_validator(mode='before')
    def validate_dependencies(cls, values) -> list:
        """Validate required fields."""

        return values
