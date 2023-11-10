import subprocess

from constants import WAZUH_CONTROL


def get_services_status() -> dict:
    """
    Get the status of the Wazuh services.
    
    Return: 
        dict: The services (keys) and their status(values).
    """
    services_status = {}

    control_output = subprocess.run([WAZUH_CONTROL, "status"], stdout=subprocess.PIPE)
    control_output_decoded = control_output.stdout.decode('utf-8')

    for line in control_output_decoded.split('\n'):
        if "running" in line:
            service_name = line.split(' ')[0]
            status = line.replace(service_name, '').replace('.', '').lstrip()
            services_status[service_name] = status

    return services_status
