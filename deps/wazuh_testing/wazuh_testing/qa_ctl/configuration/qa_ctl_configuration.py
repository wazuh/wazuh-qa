
class QACTLConfiguration:
    """Class implemented to control the different options for the output config module.

    Args:
        configuration_data (dict) : Dict with all the info needed for this module coming from config file.
        script_parameters (argparse.Namespace): qa-ctl script parameters object.
    Attributes:
        configuration_data (dict) : Dict with all the info needed for this module coming from config file.
        vagrant_output (boolean): Defines if the vagrant's outputs are going to be replaced by customized
        outputs or if they remain with the default outputs. This parameter is set to 'False' by default.
        ansible_output (boolean): Defines if the ansible's outputs are going to be replaced by customized
        outputs or if they remain with the default outputs. This parameter is set to 'False' by default.
        logging_enable (boolean): This field is used for enabling or disabling the logging outputs option.
        Its default value is set to 'True'.
        logging_level (string): Defines the logging level for the outputs.
        Four options are available: DEBUG, INFO, WARNING, ERROR, CRITICAL.
        logging_file (string): This field defines a path for a file where the outputs will be logged as well
        qa_ctl_launcher_branch (str): QA branch to launch the qa-ctl tool in the docker container (for Windows native)
    """

    def __init__(self, configuration_data, script_parameters):
        self.configuration_data = configuration_data
        self.vagrant_output = False
        self.ansible_output = False
        self.logging_enable = True
        self.logging_level = 'INFO'
        self.logging_file = None
        self.qa_ctl_launcher_branch = None
        self.script_parameters = script_parameters
        self.debug_level = script_parameters.debug

        self.__read_configuration_data()

        # Check debug level parameter set in qa-ctl script parameters. It has a higher priority than indicated in
        # the configuration file.
        if self.debug_level == 1:
            self.logging_level = 'DEBUG'
        if self.debug_level > 1:
            self.vagrant_output = True
            self.ansible_output = True

    def __read_configuration_data(self):
        """Read the given configuration data of the object and sets the values of the parameters of the class."""

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
            if 'qa_ctl_launcher_branch' in self.configuration_data['config']:
                self.qa_ctl_launcher_branch = self.configuration_data['config']['qa_ctl_launcher_branch']

    def __str__(self):
        """Define how the class object is to be displayed."""
        return f"vagrant_output: {self.vagrant_output}\nansible_output: {self.ansible_output}\n" \
               f"logging_enable: {self.logging_enable}\nloggin_level: {self.logging_level}\n"\
               f"logging_file: {self.logging_file}\nqa_ctl_launcher_branch:{self.qa_ctl_launcher_branch}\n"
