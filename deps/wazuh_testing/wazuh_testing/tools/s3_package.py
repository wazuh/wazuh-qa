

def get_version(self, version):
    tokens = version.split('.')
    def_version = f"{tokens[0]}+{tokens[1]}"
    return def_version


def is_repository(self, repo):
    repository_list = ['pre-release', 'futures', 'debug', 'trash', 'staging', 'live']
    non_repository_list = ['warehouse-branches', 'warehouse-pullrequests', 'warehouse-test']
    is_repo = False

    if repo in repository_list:
        is_repo = True
    elif repo in non_repository_list:
        is_repo = False

    return is_repo

def generate_repository_url(self, s3_path, package_name, s3_bucket, short_url=False):
    if short_url == True:
        url = f"https://{s3_bucket}/{s3_path}/{package_name}"
    else:
        url = f"https://s3-us-west-1.amazonaws.com/{s3_bucket}/{s3_path}/{package_name}"
    
    return url

def generate_non_repository_url(self, target, version, system, revision, repository, architecture):
    non_repository_url = 'https://packages-dev.wazuh.com/'
    fixed_version = get_version(version)

    if repository == 'warehouse-branches':
        non_repository_url += f"warehouse/branches/{fixed_version}/"
    elif repository == 'warehouse-pullrequests':
        non_repository_url += f"warehouse/pullrequests/{fixed_version}/"
    elif repository == 'warehouse-test':
        non_repository_url += f"warehouse/test/{fixed_version}/"
    else:
        print("error")          #Error messages?!
    
    
    if system == 'rpm' or system == 'rpm5' or system == 'deb':
        non_repository_url += 'var/'
    
    package_name = get_package_name(target, version, system, revision, repository, architecture)
    non_repository_url += package_name

    return non_repository_url

    
def get_package_name(self, target, version, system, revision, repository, architecture):
    package_name = 'wazuh-'
    if architecture == 'i386':
        deb_architecture = 'i386'
        rpm_architecture = 'i386'
    elif architecture == 'x86_64':
        deb_architecture = 'amd64'
        rpm_architecture = architecture
    elif architecture == 'arm64v8':
        deb_architecture = 'arm64'
        rpm_architecture = 'aarch64'
    elif architecture == 'arm32v7':
        deb_architecture = 'armhf'
        rpm_architecture = 'armv7hl'
    else:
        print ("Error")     #Error messages?!

    package_name += target

    if system == 'rpm':
        package_name += f"-{version}-{revision}.{rpm_architecture}.rpm"
    elif system == 'deb':
        package_name += f"_{version}-{revision}_{deb_architecture}.deb"
    elif system == 'windows':
        package_name += f"-{version}-{revision}.msi"
    elif system == ' macos':
        package_name += f"-{version}-{revision}.pkg"
    elif system == 'solaris10':
        package_name += f"_v{version}"
        if repository != 'live':
            if repository  != 'pre-release':
                package_name += f"-{revision}"
        package_name += f"-sol10-{architecture}.pkg"
    elif system == 'solaris11':
        package_name += f"_v{version}"
        if repository != 'live':
            if repository  != 'pre-release':
                package_name += f"-{revision}"
        package_name += f"-sol11-{architecture}.p5p"
    elif system == 'rpm5':
        package_name += f"-{version}-{revision}.el5.{rpm_architecture}.rpm"
    elif system == 'wpk-linux':
        if revision  != '1':
            revision_part = f"-{revision}"
        package_name = f"wazuh_agent_v{version}{revision_part}_linux_x86_64.wpk"
    elif system == 'wpk-windows':
        if revision  != '1':
            revision_part = f"-{revision}"
        package_name = f"wazuh_agent_v{version}{revision_part}_windows.wpk"
    else:
        print("Error")   #Error messages?!
    
    return package_name


def get_s3_package_url(self, repository, target, version, revision, system, architecture):
    if is_repository(repository):
        s3_bucket = 'packages-dev.wazuh.com'

        if repository == 'live':
            s3_bucket = 'packages.wazuh.com'
            s3_path = get_version(version)             #solve 
        else:
            s3_path = repository
        
        if system == 'rmp':
            s3_path += 'yum'
        elif system == 'deb':
            s3_path += f"apt/pool/main/w/wazuh-{target}"
        elif system == 'windows':
            s3_path += 'windows'
        elif system == 'macos':
            if repository == 'live':
                s3_path += 'osx'
            else:
                s3_path += 'macos'
        elif system == 'solaris10':
            s3_path += f"solaris/{architecture}/10"
        elif system == 'solaris11':
            s3_path += f"solaris/{architecture}/11"
        elif system == 'rpm5':
            s3_path += f"yum5/{architecture}"
        else:
            print("error")              #error messages?!
        
        package_name = get_package_name(target, version, system, revision, repository, architecture)
        return generate_repository_url(s3_path, package_name, s3_bucket, True)
    else:
        return generate_non_repository_url(self, target, version, system, revision, repository, architecture)
        