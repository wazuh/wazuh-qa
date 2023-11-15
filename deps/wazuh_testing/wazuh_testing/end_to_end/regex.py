
regex = {
    'syscollector_scan_start': {
        'regex': '.*INFO: Starting evaluation.'
    },
    'syscollector_scan_end': {
        'regex': '.*INFO: Starting evaluation.'
    },
    'syscollector_install_package_alert_yum': {
        'regex': '.*installed.*agent".*"name":"(\S+)".*Installed: (\S+).*?(\S+)',
        'parameters': ['PACKAGE_NAME', 'PACKAGE_VERSION', 'HOST_NAME']
    },
    'syscollector_install_package_alert_apt': {
        'regex': '.*New dpkg \(Debian Package\) installed.*.*agent".*"name":"(\S+).*package":"(\S+)","arch":"amd64","version":"(\S+)"',
        'parameters': ['HOST_NAME', 'PACKAGE_NAME', 'PACKAGE_VERSION']
    },
    'syscollector_upgrade_package_alert_yum': {
        'regex': '.*Yum package updated.*agent".*"name":"(\S+)".*Updated: (\S+).*?(\S+)',
        'parameters': ['PACKAGE_NAME', 'PACKAGE_VERSION', 'HOST_NAME']
    },
    'vulnerability_alert':{
        'regex': '.*HOST_NAME.*package:.*name":"PACKAGE_NAME".*version":"PACKAGE_VERSION".*"architecture":"ARCHITECTURE.*"cve":"CVE"',
        'parameters': ['HOST_NAME', 'CVE', 'PACKAGE_NAME', 'PACKAGE_VERSION', 'ARCHITECTURE']
    }
}


def get_event_regex(event):
    """
    """
    expected_event = regex[event['event']]
    expected_regex = expected_event['regex']

    if 'parameters' in expected_event and not 'parameters' in event:
        raise Exception(f"Not provided enaugh data to create regex. Missing {event['PARAMETERS']}")
    elif 'parameters' in event:
        for parameter in expected_event['parameters']:
            expected_regex = expected_regex.replace(parameter, event['parameters'][parameter])


    return expected_regex
