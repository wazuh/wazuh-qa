from pathlib import Path
import typing
from pydantic import BaseModel, validator, model_validator, IPvAnyAddress


class InputPayload(BaseModel):
    inventory_agent: Path | None
    inventory_manager: Path | None
    inventory: Path | None
    install: list | None
    custom_credentials: str | None
    manager_ip: Path | None

    @validator("install", pre=True)
    def set_install(cls, install_list) -> typing.List[str]:
      """
      Valdiate and set the install list.

      Args:
          install_list: List of components to install.
      """
      if not install_list:
        return []
      install = list(filter(None, install_list.split(",")))
      return install

    @model_validator(mode="before")
    def validate_inventory(cls, values):
      """
      Validate the inventory.

      Args:
          values: InputPayload model.
      """
      if values.get('inventory_agent') and values.get('inventory_manager'):
        values['manager_ip'] = values['inventory_manager']
        values['inventory'] = values.get('inventory_agent')
      elif values.get('inventory_manager'):
        values['inventory'] = values.get('inventory_manager')
        values['manager_ip'] = None
      else:
        raise ValueError("Inventory agent is required when inventory manager is provided")

      return values