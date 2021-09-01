# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


systems = {
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

architectures = {
    'i386': 'i386',
    'sparc': 'sparc',
    'x86_64': 'x86_64',
    'amd64': 'amd64',
    'arm64v8': 'arm64v8',
    'arm32v7': 'arm32v7'
}

def get_version(version):
    """Format the version

    Args:
        version (string) : String containing the version

    Returns:
        str: String with the version in a usable format for the tool
    """
    tokens = version.split('.')
    def_version = f"{tokens[0]}.{tokens[1]}"
    return def_version



def is_repository(repo):
    """Check if the directory is a repo type in the S3 server

    Args:
        repo (string): String with the directory name  

    Returns:
        boolean: True if the directory is a repo, false otherwise.
    """
    repository_list = ['pre-release', 'futures', 'debug', 'trash', 'staging', 'live']
    non_repository_list = ['warehouse-branches', 'warehouse-pullrequests', 'warehouse-test']
    is_repo = False

    if repo in repository_list:
        is_repo = True
    elif repo in non_repository_list:
        is_repo = False

    return is_repo

def generate_repository_url(s3_path, package_name, s3_bucket, short_url=True):
    """Generate the url for a package of a repository type directory
    
    Args:
        s3_path (string): Path with the s3_path where the package is locate
        package_name (string): String with the name of the package
        s3_bucket (string): String with the s3 bucket type
        short_url (boolean): Defines wether if the url is going to be a short type or not.
                            This parameter is set to False by default. 
    
    Returns:
        str: The url of the given package
    """
    if short_url == True:
        url = f"https://{s3_bucket}/{s3_path}/{package_name}"
    else:
        url = f"https://s3.us-west-1.amazonaws.com/{s3_bucket}/{s3_path}/{package_name}"
    
    return url

def generate_non_repository_url( target, version, system, revision, repository, architecture, s3_bucket, short_url=True):
    """Generate the url for a package of a non-repository type directory
    
    Args:
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        system (string): System desired for the installation version
        revision (string): Revisision of the package version
        repository (string): non-repository directory where the package is located
        architecture (string): Architecture of the package
        s3_bucket (string): String with the s3 bucket type
        short_url (boolean): Defines wether if the url is going to be a short type or not.
                            This parameter is set to False by default.
    
    Returns:
        str: The url of the given package
    """
    if short_url == True:
        non_repository_url = f"https://{s3_bucket}/"
    else:
        non_repository_url = f"https://s3.us-west-1.amazonaws.com/{s3_bucket}/"

    fixed_version = get_version(version)

    if repository == 'warehouse-branches':
        non_repository_url += f"warehouse/branches/{fixed_version}/"
    elif repository == 'warehouse-pullrequests':
        non_repository_url += f"warehouse/pullrequests/{fixed_version}/"
    elif repository == 'warehouse-test':
        non_repository_url += f"warehouse/test/{fixed_version}/"
    else:
        print("generate_non_repository_url error")          
    
    
    if system == systems['rpm'] or system == systems['rpm5'] or system == systems['deb']:
        if repository == 'warehouse-test' and fixed_version == '4.1':
            non_repository_url += f"{system}/opt/"
        else:
            non_repository_url += f"{system}/var/"
        
    elif system == systems['solaris10']:
        non_repository_url += "solaris/i386/10/"
    elif system == systems['solaris11']:
        non_repository_url += "solaris/i386/11/"
    elif system ==systems['windows'] or system == systems['macos']:
        non_repository_url += f"{system}/"
    elif system == systems['wpk-windows']:
        non_repository_url += "wpk/windows/"
    elif system == systems['wpk-linux']:
        non_repository_url += "wpk/linux/"

    
    package_name = get_package_name(target, version, system, revision, repository, architecture)
    non_repository_url += package_name
    return non_repository_url

    
def get_package_name( target, version, system, revision, repository, architecture):
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

    if architecture == architectures['i386']:
        deb_architecture = architecture
        rpm_architecture = architecture
    if architecture == architectures['sparc']:
        deb_architecture = architecture
        rpm_architecture = architecture
    elif architecture == architectures['x86_64']:
        deb_architecture = 'amd64'
        rpm_architecture = architecture
    elif architecture == architectures['amd64']:
        deb_architecture = architecture
        rpm_architecture = 'x86_64'
    elif architecture == architectures['arm64v8']:
        deb_architecture = 'arm64'
        rpm_architecture = 'aarch64'
    elif architecture == architectures['arm32v7']:
        deb_architecture = 'armhf'
        rpm_architecture = 'armv7hl'
    else:
        print ("get_package_name  architecture section error ") 


    package_name += target

    if system == systems['rpm']:
        package_name += f"-{version}-{revision}.{rpm_architecture}.rpm"
    elif system == systems['deb']:
        package_name += f"_{version}-{revision}_{deb_architecture}.deb"
    elif system == systems['windows']:
        package_name += f"-{version}-{revision}.msi"
    elif system == systems['macos']:
        package_name += f"-{version}-{revision}.pkg"
    elif system == systems['solaris10']:
        package_name += f"_v{version}"
        if repository != 'live':
            if repository  != 'pre-release':
                package_name += f"-{revision}"
        package_name += f"-sol10-{architecture}.pkg"
    elif system == systems['solaris11']:
        package_name += f"_v{version}"
        if repository != 'live':
            if repository  != 'pre-release':
                package_name += f"-{revision}"
        package_name += f"-sol11-{architecture}.p5p"
    elif system == systems['rpm5']:
        package_name += f"-{version}-{revision}.el5.{rpm_architecture}.rpm"
    elif system == systems['wpk-linux']:
        revision_part = ''
        if revision  != '1':
            revision_part = f"-{revision}"
        package_name = f"wazuh_agent_v{version}{revision_part}_linux_x86_64.wpk"
    elif system == systems['wpk-windows']:
        revision_part = ''
        if revision  != '1':
            revision_part = f"-{revision}"
        package_name = f"wazuh_agent_v{version}{revision_part}_windows.wpk"
    else:
        print("get_package_name system section error ")   
    
    return package_name


def get_s3_package_url(repository, target, version, revision, system, architecture, short_url=True):
    """Generate the url for a package of the s3 servers
    Args:
        target (string): Type of the wazuh installation package.
        version (string): Version of the installation package
        system (string): System desired for the installation version
        revision (string): Revisision of the package version
        repository (string): non-repository directory where the package is located
        architecture (string): Architecture of the package
        s3_bucket (string): String with the s3 bucket type
        short_url (boolean): Defines wether if the url is going to be a short type or not.
                            This parameter is set to False by default.
    
    Returns:
        str: The url of the desired package
    """
    if is_repository(repository):
        s3_bucket = 'packages-dev.wazuh.com'

        if repository == 'live':
            s3_bucket = 'packages.wazuh.com'
            tokens = version.split('.')
            def_version = f"{tokens[0]}.x"
            s3_path = f"{def_version}/"            
        else:
            s3_path = f"{repository}/"
        

        if system == systems['rpm']:
            s3_path += 'yum'
        elif system == systems['deb']:
            s3_path += f"apt/pool/main/w/wazuh-{target}"
        elif system == systems['windows']:
            s3_path += 'windows'
        elif system == systems['macos']:
            s3_path += 'macos'
        elif system == systems['solaris10']:
            s3_path += f"solaris/{architecture}/10"
        elif system == systems['solaris11']:
            s3_path += f"solaris/{architecture}/11"
        elif system == systems['rpm5']:
            s3_path += f"yum5/{architecture}"
        elif system == systems['wpk-linux']:
            s3_path += f"wpk/linux/{architecture}"
        elif system == systems['wpk-windows']:
            s3_path += f"wpk/windows/{architecture}"
        else:
            print("get_s3_package_url error")              
        
        package_name = get_package_name(target, version, system, revision, repository, architecture, short_url)
        result_tmp = generate_repository_url(s3_path, package_name, s3_bucket)
        print(result_tmp)
        return result_tmp
    else:
        s3_bucket = 'packages-dev.wazuh.com'
        result_tmp =  generate_non_repository_url( target, version, system, revision, repository, architecture, s3_bucket, short_url)
        print(result_tmp)
        return result_tmp
        