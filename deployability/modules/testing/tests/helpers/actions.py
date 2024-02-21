import time
import subprocess
import os
import platform

from . import utils


def install_wazuh_agent(os_type, wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, type_os=None, architecture=None):
    """
    Install Wazuh agent based on the provided OS type and parameters.

    Args:
        os_type (str): The target operating system ('linux', 'windows', 'macos').
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.
        type_os (str): Type of linux os (rpm, deb).
        architecture: (str): Type of architecture (aarch64, x86_64, intel, apple).

    Returns:
        None
    """
    if os_type == 'linux':
        install_linux_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, type_os, architecture)
    elif os_type == 'windows':
        install_windows_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip)
    elif os_type == 'macos':
        install_macos_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, architecture)
    else:
        print("Unsupported operating system.")

def install_linux_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, type_os, architecture):
    """
    Install Wazuh agent on Linux.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.
        type_os (str): Type of linux os (rpm, deb).
        architecture: (str): Type of architecture (aarch64, x86_64, intel, apple).

    Returns:
        None
    """

    base_url = f"https://{aws_s3}/{repository}/yum/wazuh-agent-{wazuh_version}-{wazuh_revision}"

    architecture_suffix = {'x86_64': 'amd64', 'aarch64': 'aarch64'}

    url = f"{base_url}.{architecture_suffix.get(architecture)}.rpm"
    download_command = f'wget {url} -O wazuh-agent_{wazuh_version}-{wazuh_revision}.{architecture}.rpm'
    install_command = f"sudo WAZUH_MANAGER='{dependency_ip}' rpm -ihv wazuh-agent-{wazuh_version}-{wazuh_revision}.{architecture}.rpm"

    if type_os == 'deb':
        architecture_suffix['x86_64'] = 'amd64'
        url = f"https://{aws_s3}.wazuh.com/{repository}/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture_suffix.get(architecture)}.deb"
        download_command = f'wget {url} -O wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture}.deb'
        install_command = f"sudo WAZUH_MANAGER='{dependency_ip}' dpkg -i ./wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture}.deb"

    try:
        subprocess.run(download_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")

    time.sleep(2)
    try:
        subprocess.run(install_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing the command: {e}")

    post_install_commands = [
        "sudo systemctl daemon-reload",
        "sudo systemctl enable wazuh-agent",
        "sudo systemctl start wazuh-agent"
    ]

    for command in post_install_commands:
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")

def install_windows_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip):
    """
    Install Wazuh agent on Windows.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.

    Returns:
        None
    """
    install_command = f"Invoke-WebRequest -Uri {aws_s3}/{repository}/windows/wazuh-agent-{wazuh_version}-{wazuh_revision}.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='{dependency_ip}' WAZUH_REGISTRATION_SERVER='{dependency_ip}'"

    utils.run_command(install_command)

    post_install_command = "NET START WazuhSvc"
    utils.run_command(post_install_command)

def install_macos_agent(wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, architecture):
    """
    Install Wazuh agent on MacOS.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.
        architecture: (str): Type of architecture (aarch64, x86_64, intel, apple).

    Returns:
        None
    """
    if architecture == 'Intel':
        command = f"curl -so wazuh-agent.pkg {aws_s3}/{repository}/macos/wazuh-agent-{wazuh_version}-{wazuh_revision}.intel64.pkg && echo 'WAZUH_MANAGER='{dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"
    elif architecture == 'Apple':
        command = f"curl -so wazuh-agent.pkg {aws_s3}/{repository}/macos/wazuh-agent-{wazuh_version}-{wazuh_revision}.arm64.pkg && echo 'WAZUH_MANAGER='{dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"

    utils.run_command(command)

    post_install_command = "sudo /Library/Ossec/bin/wazuh-control start"
    utils.run_command(post_install_command)

def uninstall_wazuh_agent(os_type, wazuh_version, wazuh_revision, type_os):
    """
    Uninstall Wazuh agent based on the provided OS type and parameters.

    Args:
        os_type (str): The target operating system ('linux', 'windows', 'macos').
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        type_os (str): Type of linux os (rpm, deb).

    Returns:
        None
    """
    if os_type == 'linux':
        uninstall_linux_agent(type_os)
    elif os_type == 'windows':
        uninstall_windows_agent(wazuh_version, wazuh_revision)
    elif os_type == 'macos':
        uninstall_macos_agent()
    else:
        print("Unsupported operating system.")

def uninstall_linux_agent(type_os):
    """
    Uninstall Wazuh agent on Linux.

    type_os (str): Type of linux os (rpm, deb).
    Returns:
        None
    """
    if type_os == 'rpm':
        uninstall_commands = ["yum remove wazuh-agent"]
    elif type_os == 'deb':
        uninstall_commands = [
        "sudo apt-get remove -y wazuh-agent",
        "sudo apt-get remove -y --purge wazuh-agent"
        ]

    for command in uninstall_commands:
        print(command)
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")

    post_uninstall_commands = [
        "systemctl disable wazuh-agent",
        "systemctl daemon-reload"
    ]

    for command in post_uninstall_commands:
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")

def uninstall_windows_agent(wazuh_version, wazuh_revision):
    """
    Uninstall Wazuh agent on Windows.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.

    Returns:
        None
    """
    uninstall_command = f"msiexec.exe /x wazuh-agent-{wazuh_version}-{wazuh_revision}.msi /qn"

    utils.run_command(uninstall_command)

def uninstall_macos_agent():
    """
    Uninstall Wazuh agent on MacOS.

    Returns:
        None
    """

    uninstall_commands = [
        "/Library/Ossec/bin/wazuh-control stop",
        "/bin/rm -r /Library/Ossec",
        "/bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist",
        "/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist",
        "/bin/rm -rf /Library/StartupItems/WAZUH",
        "/usr/bin/dscl . -delete \"/Users/wazuh\"",
        "/usr/bin/dscl . -delete \"/Groups/wazuh\"",
        "/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent"
    ]

    for command in uninstall_commands:
        utils.run_command(command)

def checkfiles(os_type):
    """
    It captures a structure of a /Var or c: directory status

    Returns:
        List: list of directories
    """
    if os_type == 'linux' or os_type == 'macos':
        command = "sudo find /var -type f -o -type d 2>/dev/null"
    elif os_type == 'windows':
        command = 'dir /a-d /b /s | findstr /v /c:"\\.$" /c:"\\..$"| find /c ":"'
    else:
        print("Unsupported operating system.")
        return None

    result = subprocess.run(command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        paths = [path.strip() for path in result.stdout.split('\n') if path.strip()]
        return paths
    else:
        print(f"Error executing command. Return code: {result.returncode}")
        return None

def get_os_type():
    """
    It returns the os_type of host

    Returns:
        str: type of host (windows, linux, macos)
    """
    system = platform.system()
    
    if system == 'Windows':
        return 'windows'
    elif system == 'Linux':
        return 'linux'
    elif system == 'Darwin':
        return 'macos'
    else:
        return 'unknown'

def perform_action_and_scan(callback):
    """
    Frame where check-file is taken before and after the callback

    Args:
        callback (callback): callback that can modify the file directory

    Returns:
        dict: added and removed files
    """
    initial_scan = checkfiles(get_os_type())

    callback()

    second_scan = checkfiles(get_os_type())

    removed = list(set(initial_scan) - set(second_scan))
    added = list(set(second_scan) - set(initial_scan))
    changes = {'added': added,
               'removed': removed
               }

    return changes

def get_achitecture():
    """
    It returns the arch of host

    Returns:
        str: arch (aarch64, x86_64, intel, apple)
    """
    return platform.machine()

def get_linux_distribution():
    """
    It returns the linux distribution of host

    Returns:
        str: linux distribution (dev, rpm)
    """
    if get_os_type() == 'linux':
        package_managers = {
            '/etc/debian_version': 'deb',
            '/etc/redhat-release': 'rpm',
        }

        for file_path, package_manager in package_managers.items():
            if os.path.exists(file_path):
                return package_manager