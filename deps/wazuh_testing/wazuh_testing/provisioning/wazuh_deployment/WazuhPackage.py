from abc import ABC, abstractmethod
import WazuhInstallation


class WazuhPackage(WazuhInstallation, ABC):

    @abstractmethod
    def download_sources():
        pass

    def __init__(self, params):
        super().__init__(params=params)
