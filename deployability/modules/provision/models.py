from pathlib import Path
from typing import List, Union
import typing
from pydantic import BaseModel, validator, model_validator
from modules.generic.utils import Utils
import json

class ComponentInfo(BaseModel):
    component: str
    type: str = ""
    version: str = ""
    manager_ip: str = None

class InputPayload(BaseModel):
  inventory_agent: Path | None
  inventory_manager: Path | None
  inventory: Path | None
  install: List[ComponentInfo] | None
  uninstall: List[ComponentInfo] | None
  manager_ip: str | None

  @model_validator(mode="before")
  def validations(cls, values):
    """
    Validate the inventory.

    Args:
        values: InputPayload model.
    """

    values.update(cls.validate_action(values))

    values.update(cls.validate_inventory(values))

    return values

  @classmethod
  def validate_action(cls, values):
    """
    Validate action.
    """
    if not values.get('install') and not values.get('uninstall'):
      raise ValueError('Invalid action: "install" or "uninstall" must be provided.')
    return values

  @classmethod
  def validate_inventory(cls, values):
    """
    Validate inventory recived.
    """
    if values.get('inventory_agent') is not None and values.get('inventory_manager') is not None:
      values['manager_ip'] = Utils.load_from_yaml(values.get('inventory_manager'), map_keys={'ansible_host': 'ansible_host'}, specific_key="ansible_host")
      values['inventory'] = values.get('inventory_agent')
    elif values.get('inventory_manager') is not None:
      values['inventory'] = values.get('inventory_manager')
      values['manager_ip'] = None
    else:
      raise ValueError("Inventory agent is required when inventory manager is provided")
    return values

  @validator('install', pre=True)
  def validate_install(cls, install) -> Union[None, List[str]]:
    """
    Generate the component info for install.
    """
    component_info = cls.validate_install_uninstall(install)
    return component_info

  @validator('uninstall', pre=True)
  def validate_uninstall(cls, uninstall) -> Union[None, List[str]]:
    """
    Generate the component info for uninstall.
    """
    component_info = cls.validate_install_uninstall(uninstall)
    return component_info

  @classmethod
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
