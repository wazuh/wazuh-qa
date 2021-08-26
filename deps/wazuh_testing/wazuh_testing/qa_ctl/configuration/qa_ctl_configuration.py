
class QACTLConfiguration:

    def __init__(self, configuration_data):
        self.configuration_data = configuration_data
        self.vagrant_output = False
        self.ansible_output = False
        self.logging_enable = True
        self.logging_level = 'INFO'
        self.logging_file = None

        self.__read_configuration_data()

    def __read_configuration_data(self):
        if 'config' in self.configuration_data:
            if 'vagrant_output' in self.configuration_data['config']:
                self.vagrant_output = self.configuration_data['config']['vagrant_output']
            if 'ansible_output' in self.configuration_data['config']:
                self.ansible_output = self.configuration_data['config']['ansible_output']
            if 'logging' in self.configuration_data['config']:
                if 'enable' in self.configuration_data['config']['logging']:
                    self.logging_enable = self.configuration_data['config']['logging']['enable']
                if 'level' in self.configuration_data['config']['logging']:
                    self.logging_level = self.configuration_data['config']['logging']['level']
                if 'file' in self.configuration_data['config']['logging']:
                    self.logging_file = self.configuration_data['config']['logging']['file']


    def __str__(self):
        return f"vagrant_output: {self.vagrant_output}\nansible_output: {self.ansible_output}\n" \
               f"logging_enable: {self.logging_enable}\nloggin_level: {self.logging_level}\n"\
               f"logging_file: {self.logging_file}\n"
