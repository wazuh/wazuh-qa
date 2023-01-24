import datetime
from time import time

from wazuh_testing.db_interface import query_wdb


def clean_table(agent_id, table):
    """Delete all table entries of the agent DB using wazuh_db.

    Args:
        agent_id (str): Agent ID.
        table (str): Table from the agent DB.
    """
    query_string = f"agent {agent_id} sql DELETE FROM {table}"
    query_wdb(query_string)


def update_last_full_scan(last_scan=0, agent_id='000'):
    """Update the last full scan of an agent.

    Args:
        last_scan (int): Last scan ID. This is compute by casting to int the result of time().
        agent_id (str): Agent ID.
    """
    query_string = f"agent {agent_id} sql UPDATE vuln_metadata SET LAST_FULL_SCAN={last_scan}"
    query_wdb(query_string)


def update_last_partial_scan(last_scan=0, agent_id='000'):
    """Update the last partial scan of an agent.

    Args:
        last_scan (int): Last scan ID. This is compute by casting to int the result of time().
        agent_id (str): Agent ID.
    """
    query_string = f"agent {agent_id} sql UPDATE vuln_metadata SET LAST_PARTIAL_SCAN={last_scan}"
    query_wdb(query_string)


def insert_hotfix(agent_id='000', scan_id=int(time()), scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                  hotfix='000000', checksum='dummychecksum'):
    """Insert a hotfix.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Last scan ID.
        scan_time (str): Scan date ("%Y/%m/%d %H:%M:%S").
        hotfix (str): ID of the hotfix value.
        checksum (str): Hotfix checksum.
    """
    query_string = f"agent {agent_id} sql INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES " \
                   f"({scan_id}, '{scan_time}', '{hotfix}', '{checksum}')"
    query_wdb(query_string)


def insert_os_info(agent_id='000', scan_id=int(time()), scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   hostname='centos8', architecture='x64', os_name='CentOS Linux', os_version='8.4', os_codename='',
                   os_major='8', os_minor='4', os_patch='', os_build='', os_platform='centos', sysname='Linux',
                   release='', version='', os_release='', checksum='dummychecksum', os_display_version='', triaged='0',
                   reference=''):
    """Insert the OS information in the agent database.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Id of the last scan.
        scan_time (str): Date of the scan with this format "%Y/%m/%d %H:%M:%S".
        hostname (str): Name of the host.
        architecture (str): Architecture of the host.
        os_name (str): Complete name of the OS.
        os_version (str): Version of the OS.
        os_codename (str): OS codename.
        os_major (str): Major version of the OS.
        os_minor (str): Minor version of the OS.
        os_patch (str): Current patch of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): OS platform.
        sysname (str): System name.
        release (str): Release of the OS.
        version (str): Version of the OS.
        os_release (str): Release of the OS.
        checksum (str): Checksum of the OS.
        os_display_version (str): Os displayed version
        triaged (str): Triaged.
        reference (str): OS reference.
    """
    query_string = f"agent {agent_id} sql INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, " \
                   'architecture, os_name, os_version, os_codename, os_major, os_minor, os_patch, os_build, ' \
                   'os_platform, sysname, release, version, os_release, os_display_version, checksum, reference, ' \
                   f"triaged) VALUES ({scan_id}, '{scan_time}', '{hostname}', '{architecture}', '{os_name}', " \
                   f"'{os_version}', '{os_codename}', '{os_major}', '{os_minor}', '{os_patch}', '{os_build}', " \
                   f"'{os_platform}', '{sysname}', '{release}', '{version}', '{os_release}', '{os_display_version}', " \
                   f"'{checksum}', '{reference}', {triaged})"

    query_wdb(query_string)


def insert_package(agent_id='000', scan_id=int(time()), format='rpm', name='custom-package-0',
                   priority='', section='Unspecified', size=99, vendor='wazuh-mocking', version='1.0.0-1.el7',
                   architecture='x64', multiarch='', description='Wazuh mocking packages', source='Wazuh QA tests',
                   location='', triaged='0', install_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), checksum='dummychecksum',
                   item_id='dummyitemid'):
    """Insert a package in the agent DB.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Last scan ID.
        format (str): Package format (deb, rpm, ...).
        name (str): Package name.
        priority (str): Released package priority.
        section (str): Package section.
        size (int): Package size.
        vendor (str): Package vendor.
        version (str): Package version.
        architecture (str): Package architecture.
        multiarch (str): Define if a package may be installed in different architectures.
        description (str): Package description.
        source (str): Package source.
        location (str): Package location.
        triaged (str): Times that the package has been installed.
        install_time (str): Installation timestamp.
        scan_time (str): Scan timestamp.
        checksum (str): Package checksum.
        item_id (str): Package ID.
    """
    arguments = locals()
    for key, value in arguments.items():
        if type(value) is str:
            if value != 'NULL':
                arguments[key] = f"'{value}'"

    query_wdb(f"agent {agent_id} sql INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, "
              f"size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged,"
              f"checksum, item_id) VALUES ({arguments['scan_id']}, {arguments['scan_time']}, {arguments['format']},"
              f"{arguments['name']}, {arguments['priority']}, {arguments['section']}, {arguments['size']},"
              f"{arguments['vendor']}, {arguments['install_time']}, {arguments['version']},"
              f"{arguments['architecture']}, {arguments['multiarch']}, {arguments['source']}, "
              f"{arguments['description']}, {arguments['location']}, {arguments['triaged']}, {arguments['checksum']},"
              f"{arguments['item_id']})")


def update_sync_info(agent_id='000', component='syscollector-packages', last_attempt=1, last_completion=1,
                     n_attempts=0, n_completions=0, last_agent_checksum=''):
    """Update the sync_info table of the specified agent for the selected component.

    Args:
        agent_id (str): Agent ID.
        component (str): Name of the component package.
        last_attempt (int): Last attempt of query
        last_completion (int): Last completion package
        n_attempts (int): Number of attempt.
        n_completions (int): Number of completion packets.
        last_agent_checksum (str): Checksum of the last agent registered.
    """
    query_wdb(f"agent {agent_id} sql UPDATE sync_info SET last_attempt = {last_attempt},"
              f"last_completion = {last_completion}, n_attempts = {n_attempts}, n_completions = {n_completions},"
              f"last_agent_checksum = '{last_agent_checksum}' where component = '{component}'")


def update_package(version, package, agent_id='000'):
    """Update version of installed package in database.

    Used to simulate upgrades and downgrades of the package given.

    Args:
        version (str): Package version.
        package (str): Package name.
        agent_id (str): Agent ID.
    """
    update_query_string = f'agent {agent_id} sql UPDATE sys_programs SET version="{version}" WHERE name="{package}"'
    query_wdb(update_query_string)


def delete_package(package, agent_id='000'):
    """Remove package from database.

    Used to simulate uninstall of the package given.

    Args:
        package (str): Package name.
        agent_id (str): Agent ID.
    """
    delete_query_string = f'agent {agent_id} sql DELETE FROM sys_programs WHERE name="{package}"'
    query_wdb(delete_query_string)


def clean_vulnerabilities_inventory(agent_id='000'):
    """Clean the vulnerabilities inventory from database.

    Args:
        agent_id (str): Agent ID.
    """
    clean_query_string = f"agent {agent_id} sql DELETE from vuln_cves"
    query_wdb(clean_query_string)


def modify_agent_scan_timestamp(agent_id='000', timestamp=0, full_scan=True):
    """Update the timestamp of the agent scans in the vuln_metadata table.

    Args:
        agent_id (str): Agent ID.
        timestamp (int): Timestamp value to set.
        full_scan (bool): True for set LAST_FULL_SCAN or False to set LAST_SCAN.
    """
    scan_type = "LAST_FULL_SCAN" if full_scan else "LAST_PARTIAL_SCAN"
    query_wdb(f"agent {agent_id} sql UPDATE vuln_metadata SET {scan_type}={timestamp}")


def delete_os_info(agent_id='000'):
    """Delete the sys_osinfo data from a specific agent.

    Args:
        agent_id (str): Agent ID.
    """
    query_wdb(f"agent {agent_id} sql DELETE FROM sys_osinfo")


def update_os_info(agent_id='000', scan_id=int(time()), scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   hostname='centos8', architecture='x64', os_name='CentOS Linux', os_version='8.4', os_codename='',
                   os_major='8', os_minor='4', os_patch='', os_build='', os_platform='centos', sysname='Linux',
                   release='', version='', os_release='', checksum='dummychecksum', os_display_version='', triaged='0',
                   reference=''):
    """Update the sys_osinfo data from a specific agent.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Id of the last scan.
        scan_time (str): Date of the scan with this format "%Y/%m/%d %H:%M:%S".
        hostname (str): Name of the host.
        architecture (str): Architecture of the host.
        os_name (str): Complete name of the OS.
        os_version (str): Version of the OS.
        os_codename (str): OS codename.
        os_major (str): Major version of the OS.
        os_minor (str): Minor version of the OS.
        os_patch (str): Current patch of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): OS platform.
        sysname (str): System name.
        release (str): Release of the OS.
        version (str): Version of the OS.
        os_release (str): Release of the OS.
        checksum (str): Checksum of the OS.
        os_display_version (str): Os displayed version
        triaged (str): Triaged.
        reference (str): OS reference.
    """
    delete_os_info(agent_id)
    insert_os_info(**locals())


def clean_sys_programs(agent_id='000'):
    """Clean all the agent packages data from the DB

      Args:
        agent_id (str): Agent ID.
    """
    clean_table(agent_id, 'sys_programs')


def get_vulnerability_status(agent_id='000', package=''):
    """Check the status of a vulnerability in the agent database table.

    Args:
        agent_id (str): Agent ID.
        package (str): Package to be checked.
    """
    query = f"agent {agent_id} sql SELECT status FROM vuln_cves WHERE name = '{package}'"

    result = query_wdb(query)[0]['status']

    return result


def get_packages_number(agent_id='000', package=''):
    """Check the number of packages in the agent database table.

    Args:
        agent_id (str): Agent ID.
        package (str): Package to be checked.
    """
    query = f"agent {agent_id} sql SELECT count(*) FROM sys_programs WHERE name = '{package}'"

    result = query_wdb(query)[0]['count(*)']

    return result


def get_vulnerability_inventory_data(agent_id='000', name=None, status=None, cve=None, version=None, type=None,
                                     architecture=None, severity=None, cvss2_score=None, cvss3_score=None):
    """Get the vulnerability inventory data according to the specified parameters.

    Args:
        agent_id (str): Agent ID.
        name (str): Vulnerability name.
        status (str): Vulnerability status.
        cve (str): Vulnerability CVE.
        version (str): Version.
        type (str): Vulnerability type.
        architecture (str): Architecture.
        severity (str): Vulnerability severity.
        cvss2_score (float): CVSS2 score.
        cvss3_score (float): CVSS3 score

    Returns:
        list(dict): Data in the DB.

    """
    # Build a dictionary with local variables
    query_parameters = locals()

    # Remove non query parameters
    del query_parameters['agent_id']

    # Define the initial query string
    query = f"agent {agent_id} sql SELECT * FROM vuln_cves"

    # Build the query string according to the specified parameters
    first_parameter = True
    for item, value in query_parameters.items():
        if value is not None:
            formated_value = f"'{value}'" if isinstance(value, str) else value

            if first_parameter:
                query += f" WHERE {item}={formated_value}"
                first_parameter = False
            else:
                query += f" AND {item}={formated_value}"

    return query_wdb(query)


def insert_vulnerability_in_agent_inventory(agent_id='000', name='', version='', architecture='', cve='',
                                            detection_time='', severity='None', cvss2_score=0, cvss3_score=0,
                                            reference='', type='PACKAGE', status='PENDING', external_references='',
                                            condition='', title='', published='', updated=''):
    """Insert a vulnerability in the agent vulnerabilities inventory.

    Args:
        agent_id (str): Agent ID.
        name (str): Vulnerability name.
        version (str): Version.
        architecture (str): Architecture.
        cve (str): Vulnerability CVE.
        detection_time (str): Vulnerability detection time.
        severity (str): Vulnerability severity.
        cvss2_score (float): CVSS2 score.
        cvss3_score (float): CVSS3 score
        reference (str): Vulnerability reference.
        type (str): Vulnerability type.
        status (str): Vulnerability status.
        external_references (str): Vulnerability external reference.
        condition (str): Vulnerability condition.
        title (str): Vulnerability title.
        published (str): Vulnerability published.
        updated (str): Vulnerability updated.
    """
    query_wdb(f"agent {agent_id} sql INSERT OR REPLACE INTO vuln_cves (name, version, architecture, cve, "
              f"detection_time, severity, cvss2_score, cvss3_score, reference, type, status, external_references,"
              f" condition, title, published, updated) VALUES ('{name}', '{version}', '{architecture}', '{cve}', "
              f"'{detection_time}', '{severity}', {cvss2_score}, {cvss3_score},'{reference}', '{type}', '{status}', "
              f"'{external_references}', '{condition}', '{title}', '{published}', '{updated}')")


def get_triaged_value_from_inventory(package_name, agent_id='000'):
    """Check the triaged of a vulnerability in the agent database table.

    Args:
        package_name (str): Package name.
        agent_id (str): Agent ID.
    """
    query = f"agent {agent_id} sql SELECT triaged FROM sys_programs WHERE name='{package_name}'"

    result = query_wdb(query)[0]['triaged']

    return result
