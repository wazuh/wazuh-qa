from pathlib import Path
from typing import List, Union
from pydantic import BaseModel, validator, model_validator


class ComponentInfo(BaseModel):
    component: str
    type: str = ""
    version: str = ""
    dependencies: dict | None = None


class InputPayload(BaseModel):
    inventory: Path | None
    install: List[ComponentInfo] | None
    uninstall: List[ComponentInfo] | None
    dependencies: dict | None = None

    @model_validator(mode="before")
    def validations(cls, values):
        """
        Validate the inventory.

        Args:
            values: InputPayload model.
        """

        values.update(cls.validate_action(values))

        return values

    @validator('dependencies', pre=True)
    def validate_inventory(cls, v) -> dict | None:
        """
        Validate inventory recived. 
        It expects a list or dict of dictionaries with the dependencies.

        Example: 
            list: [{'manager': 'path/to/inventory.yaml'}, {'agent': 'path/to/inventory.yaml'}]
            dict:  {'manager': 'path/to/inventory.yaml', 'agent': 'path/to/inventory.yaml'}
        """
        if v is None:
            return
        if isinstance(v, list):
            return {k: v for dep in v for k, v in eval(dep).items()}
        if isinstance(v, str):
            return {k: v for dep in eval(v) for k, v in dep.items()}
        return v

    @classmethod
    def validate_action(cls, values):
        """
        Validate action.
        """
        if not values.get('install') and not values.get('uninstall'):
            raise ValueError(
                'Invalid action: "install" or "uninstall" must be provided.')
        return values

    @validator('install', 'uninstall', pre=True)
    def validate_install_uninstall(cls, components) -> Union[None, List[str]]:
        if not components:
            return
        component_info = []
        for item in components:
            componentObj = ComponentInfo(**eval(item))
            if not componentObj.type:
                componentObj.type = "generic"
            if "wazuh-agent" in componentObj.component:
                componentObj.type = "package"
            component_info.append(componentObj)

        return component_info