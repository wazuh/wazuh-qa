class AnsibleInstance():

    def print_data(self):
        print(f'Host information: \n \
              \thost: {self.host} \n \
              \tconnection_method: {self.connection_method} \n \
              \tconnection_port: {self.connection_port} \n \
              \tconnection_user: {self.connection_user} \n \
              \tpassword: {self.connection_user_password} \n \
              \tgroup: {self.group} \n \
              \tgroup_vars: {self.group_vars} \n \
              \tconnection_user_password: {self.connection_user_password} \n \
              \tssh_private_key_file_path: {self.ssh_private_key_file_path} \n \
              \tansible_python_interpreter: {self.ansible_python_interpreter} \n')

    def __init__(self, host, host_vars, connection_method, connection_port, connection_user, connection_user_password,
                 ssh_private_key_file_path, ansible_python_interpreter):
        self.host = host
        self.host_vars = host_vars
        self.connection_method = connection_method
        self.connection_port = connection_port
        self.connection_user = connection_user
        self.connection_user_password = connection_user_password
        self.ssh_private_key_file_path = ssh_private_key_file_path
        self.ansible_python_interpreter = ansible_python_interpreter
