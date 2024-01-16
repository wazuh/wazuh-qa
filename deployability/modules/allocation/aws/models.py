from modules.allocation.generic.models import ProviderConfig


class AWSConfig(ProviderConfig):
    ami: str
    zone: str
    user: str
    key_name: str
    type: str
    security_groups: list[str]
