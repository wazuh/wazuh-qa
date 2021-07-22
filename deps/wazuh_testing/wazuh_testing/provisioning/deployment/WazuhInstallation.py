from abc import ABC, abstractmethod
import sys
import os
import shutil
from git import Repo


class WazuhInstallation(ABC):
    target: str
    target_path: str

    @abstractmethod
    def download_sources(params):
        pass

    def __init__(self, target, target_path):
        self.target = target
        self.target_path = target_path
        super().__init__()
