from . import utils
import time
import subprocess
from pathlib import Path
import subprocess

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
        architecture: (str): Type of architecture (aarch64, amd64, intel, apple).

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
        architecture: (str): Type of architecture (aarch64, amd64, intel, apple).

    Returns:
        None
    """

    # Define common parts of the URL and file names
    base_url = f"https://{aws_s3}/{repository}/yum/wazuh-agent-{wazuh_version}-{wazuh_revision}"

    # Map architectures to their corresponding suffixes
    architecture_suffix = {'amd64': 'x86_64', 'aarch64': 'aarch64'}

    # Construct URL, download, and install commands
    url = f"{base_url}.{architecture_suffix.get(architecture)}.rpm"
    download_command = f'wget {url} -O wazuh-agent_{wazuh_version}-{wazuh_revision}.{architecture}.rpm'
    install_command = f"sudo WAZUH_MANAGER='{dependency_ip}' rpm -ihv wazuh-agent-{wazuh_version}-{wazuh_revision}.{architecture}.rpm"

    # Adjust for Debian-based systems
    if type_os == 'deb':
        architecture_suffix['amd64'] = 'amd64'
        url = f"https://{aws_s3}.wazuh.com/{repository}/apt/pool/main/w/wazuh-agent/wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture_suffix.get(architecture)}.deb"
        download_command = f'wget {url} -O wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture}.deb'
        install_command = f"sudo WAZUH_MANAGER='{dependency_ip}' dpkg -i ./wazuh-agent_{wazuh_version}-{wazuh_revision}_{architecture}.deb"

    # Download agent
    try:
        subprocess.run(download_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")

    time.sleep(2)
    # Install agent
    #subprocess.run("tree", shell=True, check=True)
    try:
        subprocess.run(install_command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing the command: {e}")

    # Post-installation steps for all Linux OS
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
    # Replace placeholders in the command with actual values
    install_command = f"Invoke-WebRequest -Uri {aws_s3}/{repository}/windows/wazuh-agent-{wazuh_version}-{wazuh_revision}.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q WAZUH_MANAGER='{dependency_ip}' WAZUH_REGISTRATION_SERVER='{dependency_ip}'"

    # Run installation command
    utils.run_command(install_command)

    # Post-installation steps for all Windows OS
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
        architecture: (str): Type of architecture (aarch64, amd64, intel, apple).

    Returns:
        None
    """
    # Replace placeholders in the commands with actual values
    if architecture == 'Intel':
        command = f"curl -so wazuh-agent.pkg {aws_s3}/{repository}/macos/wazuh-agent-{wazuh_version}-{wazuh_revision}.intel64.pkg && echo 'WAZUH_MANAGER='{dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"
    elif architecture == 'Apple':
        command = f"curl -so wazuh-agent.pkg {aws_s3}/{repository}/macos/wazuh-agent-{wazuh_version}-{wazuh_revision}.arm64.pkg && echo 'WAZUH_MANAGER='{dependency_ip}'' > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /"

    # Run installation commands
    utils.run_command(command)

    # Post-installation steps for all MacOS OS
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
    # Linux uninstallation commands
    
    if type_os == 'rpm':
        uninstall_commands = ["yum remove wazuh-agent"]
    elif type_os == 'deb':
        uninstall_commands = [
        "sudo apt-get remove -y wazuh-agent",
        "sudo apt-get remove -y --purge wazuh-agent"
        ]

    # Run uninstallation commands
    for command in uninstall_commands:
        print(command)
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")
        
    # Post-uninstallation steps for all Linux OS
    post_uninstall_commands = [
        "systemctl disable wazuh-agent",
        "systemctl daemon-reload"
    ]

    # Run post-uninstallation commands
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
    # Replace placeholders in the command with actual values
    uninstall_command = f"msiexec.exe /x wazuh-agent-{wazuh_version}-{wazuh_revision}.msi /qn"

    # Run uninstallation command
    utils.run_command(uninstall_command)

def uninstall_macos_agent():
    """
    Uninstall Wazuh agent on MacOS.

    Returns:
        None
    """
    # MacOS uninstallation commands
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

    # Run uninstallation commands
    for command in uninstall_commands:
        utils.run_command(command)

def checkfiles(os_type):
    if os_type == 'linux' or os_type == 'macos':
        command = "sudo find /var/ossec -type f -o -type d  | wc -l"
    elif os_type == 'windows':
        command = 'dir /a-d /b /s | findstr /v /c:"\\.$" /c:"\\..$"| find /c ":"'
    else:
        print("Unsupported operating system.")
        return None

    result = subprocess.run(command, shell=True, executable="/bin/bash", stdout=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        print(f"Error executing command. Return code: {result.returncode}")
        return None
    
import os
import hashlib

def scan_directory(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_list.append((file_path, get_file_hash(file_path)))
    return file_list

def get_file_hash(file_path):
    hasher = hashlib.md5()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
        except OSError as e:
            print(f"Failure opening the file {file_path}: {e}")
    else:
        print(f"The {file_path} does not exist.")
        return None
    return hasher.hexdigest()

def compare_directories(old_scan, new_scan):
    changed_files = []
    added_files = []
    deleted_files = []
    total_files = {}

    # Identify modified and added files
    for new_file, new_hash in new_scan:
        file_found = False
        for old_file, old_hash in old_scan:
            if os.path.relpath(old_file) == os.path.relpath(new_file):
                file_found = True
                if old_hash != new_hash:
                    changed_files.append((new_file))

        # If the file is not found in the initial scan, consider it added
        if not file_found:
            added_files.append((new_file))

    # Identify deleted files
    for old_file, _ in old_scan:
        if os.path.relpath(old_file) not in (os.path.relpath(new_file) for new_file, _ in new_scan):
            deleted_files.append((old_file))

    total_files = {'changed_files' : changed_files,
                   'added_files': added_files,
                   'deleted_files': deleted_files
                   }

    return total_files


















def install_wazuh_agent(os_type, wazuh_version, wazuh_revision, aws_s3, repository, dependency_ip, type_os=None, architecture=None):
    """
    Install Wazuh agent based on the provided OS type and parameters.

    Args:
        os_type (str): The target operating system ('debian' or 'redhat').
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.
        type_os (str): Type of Linux OS (rpm, deb) - applicable only for 'linux' OS type.
        architecture: (str): Type of architecture (aarch64, amd64, intel, apple) - applicable only for 'macos' OS type.

    Returns:
        None
    """
    if os_type == 'redhat':
        # Red Hat Installation
        redhat_installation_commands(wazuh_version, wazuh_revision, aws_s3, repository)
    elif os_type == 'debian':
        # Debian Installation
        debian_installation_commands(wazuh_version, wazuh_revision, aws_s3, repository)
    else:
        print("Unsupported operating system.")


def redhat_installation_commands(wazuh_version, wazuh_revision, aws_s3, repository):
    """
    Install Wazuh agent on Red Hat.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.
        dependency_ip (str): IP address of the Wazuh manager.

    Returns:
        None
    """

    subprocess.run(["rpm", "--import", f"https://{aws_s3}.wazuh.com/key/GPG-KEY-WAZUH"])
    repo_config = f"[wazuh]\ngpgcheck=1\ngpgkey=https://{aws_s3}.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://{aws_s3}.wazuh.com/{repository}/yum/\nprotect=1"
    subprocess.run(["echo", "-e", repo_config, "|", "tee", "/etc/yum.repos.d/wazuh.repo"])
    subprocess.run(["yum", "-y", "install", "wazuh-manager"])

    # Common post-installation commands
    post_installation_commands()


def debian_installation_commands(wazuh_version, wazuh_revision, aws_s3, repository):
    """
    Install Wazuh agent on Debian.

    Args:
        wazuh_version (str): The version of Wazuh agent.
        wazuh_revision (str): The revision of Wazuh agent.
        aws_s3 (str): AWS S3 base URL.
        repository (str): Wazuh repository URL.

    Returns:
        None
    """

    subprocess.run(["apt-get", "install", "gnupg", "apt-transport-https"])
    subprocess.run(["curl", "-s", f"https://{aws_s3}.wazuh.com/key/GPG-KEY-WAZUH", "|", "gpg", "--no-default-keyring", "--keyring", "gnupg-ring:/usr/share/keyrings/wazuh.gpg", "--import", "&&", "chmod", "644", "/usr/share/keyrings/wazuh.gpg"])
    repo_config = f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://{aws_s3}.wazuh.com/{repository}/apt/pool/main/w/wazuh-manager/wazuh-manager_{wazuh_version}-{wazuh_revision}_amd64.deb"
    subprocess.run(["echo", repo_config, "|", "tee", "-a", "/etc/apt/sources.list.d/wazuh.list"])
    subprocess.run(["apt-get", "update"])
    subprocess.run(["apt-get", "-y", "install", "wazuh-manager"])

    # Common post-installation commands
    post_installation_commands()


def post_installation_commands():
    """
    Common post-installation commands for both Red Hat and Debian.

    Returns:
        None
    """

    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "wazuh-manager"])
    subprocess.run(["systemctl", "start", "wazuh-manager"])


# Example usage:
install_wazuh_agent('redhat', '4.0.0', '1', 'https://example.s3.amazonaws.com', 'https://example.repo.com', '192.168.1.1')
