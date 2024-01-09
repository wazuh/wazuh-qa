import os, subprocess, sys
from pathlib import Path
import yaml

class Utils:
  @staticmethod
  def get_template_list(path) -> list[Path]:
    """
    Get the list of templates in the path.

    Args:
        path: Path to the templates.
    """
    list_tasks = []
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_file():
                list_tasks.append(entry.name)
    return list_tasks

  @staticmethod
  def load_from_yaml(file_path, map_keys=None, specific_key=None):
    """
    Load data from a yaml file.

    Args:
        file_path: Path to the yaml file.
        map_keys: Map of keys to change.
    """
    data = yaml.safe_load(open(file_path))

    if map_keys:
      data = {map_keys[k]: v for k, v in data.items() if k in map_keys}

    if specific_key:
      return data.get(specific_key)

    return data