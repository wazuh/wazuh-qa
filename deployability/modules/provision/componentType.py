

class ComponentType:
    def __init__(self, component_info):
        self.component = component_info.component
        self.type = component_info.type
        self.version = component_info.version
        self.manager_ip = component_info.manager_ip or None

    def get_templates_path(self, action):
        pass

    def get_templates_order(self, action):
        pass

    def generate_dict(self):
        variables = {
                    'component': self.component,
                    'version': self.version,
                    'version': self.type,
                    'manager_ip': self.manager_ip,
                    'templates_path': self.templates_path,
                    'templates_order': self.templates_order or None
                }

        return variables

class Package(ComponentType):
    TEMPLATE_BASE_PATH = 'provision/wazuh'

    def __init__(self, component_info, action):
        super().__init__(component_info)
        self.templates_path = f'{self.TEMPLATE_BASE_PATH}/{self.type}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action):
        if action == "install":
            return ["set_repo.j2", "install.j2", "register.j2", "service.j2"]
        return []

class AIO(ComponentType):
    TEMPLATE_BASE_PATH = 'provision/wazuh'

    def __init__(self, component_info, action):
        super().__init__(component_info)
        self.templates_path = f'{self.TEMPLATE_BASE_PATH}/{self.type}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action):
        return ["download.j2", f"{action}.j2"]

class Generic(ComponentType):
    TEMPLATE_BASE_PATH = 'provision/generic'

    def __init__(self, component_info, action):
        super().__init__(component_info)
        self.templates_path = f'{self.TEMPLATE_BASE_PATH}/{action}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action):
        return []

class Dependencies(ComponentType):
    TEMPLATE_BASE_PATH = 'provision/deps'

    def __init__(self, component_info, action):
        super().__init__(component_info)
        self.templates_path = f'{self.TEMPLATE_BASE_PATH}'
        self.templates_order = self.get_templates_order(action)
        self.variables_dict = self.generate_dict()

    def get_templates_order(self, action):
        return []
