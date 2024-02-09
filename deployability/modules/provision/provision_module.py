from abc import ABC, abstractmethod

from .models import InputPayload


class ProvisionModule(ABC):
    @abstractmethod
    def run(self, payload: InputPayload):
        """
        Run Provision Module.

        Args:
			payload (InputPayload): model with the input data.
        """
        pass

    @abstractmethod
    def update_status(self, status: dict):
        """
        Update Status.

        Args:
			status: Result status.
        """
        pass

    @abstractmethod
    def install_host_dependencies(self):
        """
        Install python dependencies on the host.
        """
