from pathlib import Path
from typing import List, Union
from pydantic import BaseModel, field_validator, validator, model_validator

from modules.generic.utils import Utils


class ComponentInfo(BaseModel):
    component: str
    type: str = ""
    version: str = ""
    dependency: str | None = None


class InputPayload(BaseModel):
  inventory_agent: Path | None
  inventory_manager: Path | None
  inventory: Path | None
  install: List[ComponentInfo] | None
  uninstall: List[ComponentInfo] | None
  dependencies: list[dict] | None = None

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
  def validate_inventory(cls, v) -> list[dict]:
    """
    Validate inventory recived.
    """
    if not v:
        return
    if all(isinstance(item, str) for item in v):
        return v

    v = {eval(item) for item in v if isinstance(item, str)}
    return v

  @classmethod
  def validate_action(cls, values):
    """
    Validate action.
    """
    if not values.get('install') and not values.get('uninstall'):
      raise ValueError('Invalid action: "install" or "uninstall" must be provided.')
    return values

  @validator('install','uninstall', pre=True)
  def validate_install_uninstall(cls, components) -> Union[None, List[str]]:
    component_info = []
    if components:

      for item in components:
        componentObj = ComponentInfo(**eval(item))
        if not componentObj.type:
          componentObj.type = "generic"
        if "wazuh-agent" in componentObj.component:
          componentObj.type = "package"
        component_info.append(componentObj)

    return component_info or None
