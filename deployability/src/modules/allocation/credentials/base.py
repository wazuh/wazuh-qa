from abc import ABC, abstractmethod


class Credentials(ABC):
    """Interface for Credentials"""

    def __init__(self, **kwargs):
        """Initialize Credentials"""
        pass

    @abstractmethod
    def get_credentials(self, **kwargs):
        """Get credentials"""
        pass

    @abstractmethod
    def set_credentials(self, **kwargs):
        """Set credentials"""
        pass

    @abstractmethod
    def delete_credentials(self, **kwargs):
        """Delete credentials"""
        pass