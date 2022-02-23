# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh_testing.tools import github_checks


PROD_BUCKET = 'packages.wazuh.com'
DEV_BUCKET = 'packages-dev.wazuh.com'
S3_REGION_URL = 's3-us-west-1'

SYSTEMS = {
    'rpm': 'rpm',
    'deb': 'deb',
    'windows': 'windows',
    'macos': 'macos',
    'solaris10': 'solaris10',
    'solaris11': 'solaris11',
    'rpm5': 'rpm5',
    'wpk-linux': 'wpk-linux',
    'wpk-windows': 'wpk-windows'
}

ARCHITECTURES = {
    'i386': 'i386',
    'sparc': 'sparc',
    'x86_64': 'x86_64',
    'amd64': 'amd64',
    'arm64v8': 'arm64v8',
    'arm32v7': 'arm32v7'
}

PACKAGE_SYSTEM_TO_ARCHITECTURE = {
    'deb': 'amd64',
    'rpm': 'x86_64',
    'rpm5': 'x86_64',
    'windows': 'i386',
    'macos': 'amd64',
    'solaris10': 'i386',
    'solaris11': 'i386',
    'wpk-linux': 'x86_64',
    'wpk-windows': 'i386',
}

OS_SYSTEM_TO_PACKAGE_SYSTEM = {
    'centos': 'rpm',
    'amazon': 'rpm',
    'ubuntu': 'deb',
    'debian': 'deb',
    'windows': 'windows',
}


def get_s3_package_url(repository, target, version, revision, system, architecture, install_dir='/var', short_url=True):
    """Generate the url for a package of the s3 servers
    Args:
        repository (string): non-repository directory where the package is located
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        revision (string): Revisision of the package version
        system (string): System desired for the installation version
        architecture (string): Architecture of the package
        install_dir (string): Wazuh installation directory
        short_url (boolean): Defines wether if the url is going to be a short type or not.

    Returns:
        str: The url of the desired package
    """
    parsed_version = version.replace('v', '')
    if is_repository(repository):
        return get_repository_url(target, parsed_version, system, revision, repository, architecture, short_url)
    else:
        return get_non_repository_url(target, parsed_version, system, revision, repository, architecture, DEV_BUCKET,
                                      install_dir, short_url)


def get_short_version(version):
    """Format the package version to a usable format type for generating the url

    Args:
        version (string) : String containing the version

    Returns:
        str: String with the version in a usable format for the tool
    """
    tokens = version.split('.')
    short_version = f"{tokens[0]}.{tokens[1]}"
    return short_version


def is_repository(folder_path):
    """Check if the directory is a S3 repository

    Args:
        folder_path (string): String with the directory name

    Returns:
        boolean: True if the directory is a repo, false otherwise.
    """
    repository_list = ['pre-release', 'futures', 'debug', 'trash', 'staging', 'live']
    non_repository_list = ['warehouse-branches', 'warehouse-pullrequests', 'warehouse-test']

    if folder_path in repository_list:
        return True
    elif folder_path in non_repository_list:
        return False
    else:
        raise ValueError(f"{folder_path} is unknown. It was not found in {repository_list} or {non_repository_list}")


def get_repository_url(target, version, system, revision, repository, architecture, short_url=True):
    """Generate the url for a package of a repository type directory

    Args:
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        revision (string): Revisision of the package version
        system (string): System desired for the installation version
        architecture (string): Architecture of the package
        short_url (boolean): Defines wether if the url is going to be a short type or not.

    Returns:
        str: The url of the given package
    """
    s3_bucket = DEV_BUCKET

    system_path = {
       SYSTEMS['rpm']: '/yum',
       SYSTEMS['deb']: f"/apt/pool/main/w/wazuh-{target}",
       SYSTEMS['windows']: '/windows',
       SYSTEMS['macos']: '/macos',
       SYSTEMS['solaris10']: f"/solaris/{architecture}/10",
       SYSTEMS['solaris11']: f"/solaris/{architecture}/11",
       SYSTEMS['rpm5']: f"/yum5/{architecture}",
       SYSTEMS['wpk-linux']: f"/wpk/linux/{architecture}",
       SYSTEMS['wpk-windows']: f"/wpk/windows"
    }

    if repository == 'live':
        s3_bucket = PROD_BUCKET
        tokens = version.split('.')
        s3_path = f"{tokens[0]}.x"
    else:
        s3_path = f"{repository}"

    try:
        s3_path += system_path[system]
    except KeyError:
        raise f"{system} is not a valid system. Allowed systems: {SYSTEMS.keys()}"

    package_name = get_package_name(target, version, system, revision, repository, architecture)

    if short_url:
        url = f"https://{s3_bucket}/{s3_path}/{package_name}"
    else:
        url = f"https://{S3_REGION_URL}/{s3_bucket}/{s3_path}/{package_name}"

    return url


def get_non_repository_url(target, version, system, revision, repository, architecture, s3_bucket, install_dir='/var',
                           short_url=True):
    """Generate the url for a package of a non-repository type directory

    Args:
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        system (string): System desired for the installation version
        revision (string): Revisision of the package version
        repository (string): non-repository directory where the package is located
        architecture (string): Architecture of the package
        s3_bucket (string): String with the s3 bucket type
        install_dir (string): Wazuh installation directory
        short_url (boolean): Defines wether if the url is going to be a short type or not.
                            This parameter is set to False by default.

    Returns:
        str: The url of the given package
    """
    if short_url:
        non_repository_url = f"https://{s3_bucket}"
    else:
        non_repository_url = f"https://{S3_REGION_URL}/{s3_bucket}"

    short_version = get_short_version(version)

    if repository == 'warehouse-branches':
        non_repository_url += f"/warehouse/branches/{short_version}"
    elif repository == 'warehouse-pullrequests':
        non_repository_url += f"/warehouse/pullrequests/{short_version}"
    elif repository == 'warehouse-test':
        non_repository_url += f"/warehouse/test/{short_version}"
    else:
        raise ValueError(f"The repository named {repository} is unknown.")

    if system == SYSTEMS['rpm'] or system == SYSTEMS['rpm5'] or system == SYSTEMS['deb']:
        non_repository_url += f"/{system}{install_dir}"
    elif system == SYSTEMS['solaris10']:
        non_repository_url += f"/solaris/{architecture}/10"
    elif system == SYSTEMS['solaris11']:
        non_repository_url += f"/solaris/{architecture}/11"
    elif system == SYSTEMS['windows'] or system == SYSTEMS['macos']:
        non_repository_url += f"/{system}"
    elif system == SYSTEMS['wpk-windows']:
        non_repository_url += "/wpk/windows"
    elif system == SYSTEMS['wpk-linux']:
        non_repository_url += "/wpk/linux"

    package_name = get_package_name(target, version, system, revision, repository, architecture)
    non_repository_url += f"/{package_name}"

    return non_repository_url


def get_package_name(target, version, system, revision, repository, architecture):
    """Generate the name of the package

    Args:
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        system (string): System desired for the installation version
        revision (string): Revisision of the package version
        repository (string): non-repository directory where the package is located
        architecture (string): Architecture of the package

    Returns:
        str: The full name of the package
    """
    package_name = 'wazuh-'

    if architecture == ARCHITECTURES['i386']:
        deb_architecture = architecture
        rpm_architecture = architecture
    elif architecture == ARCHITECTURES['sparc']:
        deb_architecture = architecture
        rpm_architecture = architecture
    elif architecture == ARCHITECTURES['x86_64']:
        deb_architecture = 'amd64'
        rpm_architecture = architecture
    elif architecture == ARCHITECTURES['amd64']:
        deb_architecture = architecture
        rpm_architecture = 'x86_64'
    elif architecture == ARCHITECTURES['arm64v8']:
        deb_architecture = 'arm64'
        rpm_architecture = 'aarch64'
    elif architecture == ARCHITECTURES['arm32v7']:
        deb_architecture = 'armhf'
        rpm_architecture = 'armv7hl'
    else:
        raise ValueError(f"{architecture} is an invalid architecture")

    package_name += target

    if system == SYSTEMS['rpm']:
        package_name += f"-{version}-{revision}.{rpm_architecture}.rpm"
    elif system == SYSTEMS['deb']:
        package_name += f"_{version}-{revision}_{deb_architecture}.deb"
    elif system == SYSTEMS['windows']:
        package_name += f"-{version}-{revision}.msi"
    elif system == SYSTEMS['macos']:
        package_name += f"-{version}-{revision}.pkg"
    elif system == SYSTEMS['solaris10'] or system == SYSTEMS['solaris11']:
        package_name += f"_v{version}"
        if repository != 'live' and repository != 'pre-release':
            package_name += f"-{revision}"
        architecture_section = f"-sol10-{architecture}.pkg" if system == SYSTEMS['solaris10'] \
            else f"-sol11-{architecture}.p5p"
        package_name += architecture_section
    elif system == SYSTEMS['rpm5']:
        package_name += f"-{version}-{revision}.el5.{rpm_architecture}.rpm"
    elif system == SYSTEMS['wpk-linux']:
        revision_section = f"-{revision}" if revision != '1' else ''
        package_name = f"wazuh_agent_v{version}{revision_section}_linux_x86_64.wpk"
    elif system == SYSTEMS['wpk-windows']:
        revision_section = f"-{revision}" if revision != '1' else ''
        package_name = f"wazuh_agent_v{version}{revision_section}_windows.wpk"
    else:
        raise ValueError(f"{system} is not a valid system")

    return package_name


def get_package_system(os_system):
    """Translate the operating system to its package system.

    Example: centos7 -> rpm, ubuntu -> deb.

    Returns:
        str: Package system from the OS system.

    Raises:
        ValueError: If the os_system was not found in the mapping data.

    """
    for key, value in OS_SYSTEM_TO_PACKAGE_SYSTEM.items():
        if key in os_system:
            return value

    # Raise exception if the os_system was not found in the OS_SYSTEM_TO_PACKAGE_SYSTEM data
    raise ValueError(f"{os_system} was not found in get_package_system mapping")


def get_production_package_url(wazuh_target, os_system, wazuh_version):
    """Get an URL from a production package (it has been released)

    Args:
        wazuh_target (str): Wazuh target (manager or agent)
        os_system (str): Operating system (e.g centos8)
        wazuh_version (str): Wazuh version (e.g 4.2.5)

    Returns:
        str: Package URL from production bucket.
    Raises:
        ValueError: If could not find an architecture for the package system.
    """
    package_system = get_package_system(os_system)

    try:
        architecture = PACKAGE_SYSTEM_TO_ARCHITECTURE[package_system]
    except KeyError as exception:
        raise ValueError(f"{package_system} is not a valid system to get the package architecture.") from exception

    return get_s3_package_url('live', wazuh_target, wazuh_version, '1', package_system, architecture)


def get_last_production_package_url(wazuh_target, os_system):
    """Get the package URL from the last released package.

    Args:
        wazuh_target (str): Wazuh target (manager or agent)
        os_system (str): Operating system (e.g centos8)

    Returns:
        str: Last released package URL from production bucket.
    """
    last_wazuh_version = github_checks.get_last_wazuh_version()

    return get_production_package_url(wazuh_target, os_system, last_wazuh_version)
