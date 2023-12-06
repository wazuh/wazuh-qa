from pathlib import Path
import jinja2
import yaml
from fnmatch import fnmatch

from deployability.src.modules.allocation.credentials.vagrant import VagrantCredential
from ..models import InstanceParams, VagrantConfig
from .interface import ProviderInterface


class VagrantProvider(ProviderInterface):

    def __init__(self, instance_params: InstanceParams, root_path: str):
        self.credential = VagrantCredential(instance_params.name, self.path)

        super().__init__(instance_params, self.__set_config(), root_path)

    def create(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def delete(self):
        pass

    def status(self):
        pass

    def get_ansible_inventory(self):
        pass

    def __set_config(self) -> VagrantConfig:
        config = {}

        roles = self.__get_role_specs('vagrant')
        os_specs = self.__get_os_specs('vagrant')
        composite_name = self.instance_params.composite_name

        config['box'] = os_specs[composite_name]['box']
        config['box_version'] = os_specs[composite_name]['box_version']
        for pattern, specs in roles[self.instance_params.role].items():
            if fnmatch(composite_name, pattern):
                config['cpu'] = specs['cpu']
                config['memory'] = specs['memory']
                config['ip'] = specs['ip']
                break

        return VagrantConfig(**config)

    def __render_vagrantfile(self) -> str:

        template_path = self.TEMPLATES_DIR / 'vagrant'
        template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        template_env = jinja2.Environment(loader=template_loader)

        loaded_template = template_env.get_template(template_path)
        return loaded_template.render(config=self.config, credential=self.credential)
