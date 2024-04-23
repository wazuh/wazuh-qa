import logging


def get_failed_operation_hosts(global_operation_results: dict) -> list:
    failed_hosts = []
    for host, operation_result in global_operation_results.items():
        if not operation_result:
            logging.critical(f"Operation on {host} failed")
            failed_hosts.append(host)

    return failed_hosts


def validate_operation_results(global_operation_results: dict) -> bool:
    return len(get_failed_operation_hosts(global_operation_results)) == 0


def compare_expected_found_vulnerabilities(vulnerabilities, expected_vulnerabilities):
    logging.critical(f"Vulnerabilities: {vulnerabilities}")
    logging.critical(f"Expected vulnerabilities: {expected_vulnerabilities}")

    result = True

    vulnerabilities_not_found = {}
    vulnerabilities_unexpected = {}

    failed_agents = []

    expected_vulnerabilities_present = expected_vulnerabilities.get('present', {})
    expected_vulnerabilities_absent = expected_vulnerabilities.get('absent', {})

    for agent, expected_vulns in expected_vulnerabilities_present.items():
        for vulnerability in expected_vulns:
            if vulnerability not in vulnerabilities.get(agent, []):
                logging.critical(f"Vulnerability not found for {agent}: {vulnerability}")
                if agent not in vulnerabilities_not_found:
                    vulnerabilities_not_found[agent] = []
                    failed_agents.append(agent)

                result = False
                vulnerabilities_not_found[agent].append(vulnerability)

    for agent, expected_vuln in expected_vulnerabilities_absent.items():
        for vulnerability in expected_vuln:
            if vulnerability in vulnerabilities.get(agent, []):
                logging.critical(f"Vulnerability unexpected: {vulnerability}")
                if agent not in vulnerabilities_unexpected:
                    vulnerabilities_unexpected[agent] = []
                    failed_agents.append(agent)

                result = False
                vulnerabilities_unexpected[agent].append(vulnerability)

    if not result:
        logging.critical(f"Vulnerabilities not found: {vulnerabilities_not_found}")
        logging.critical(f"Vulnerabilities unexpected: {vulnerabilities_unexpected}")

    return {
                'vulnerabilities_not_found': vulnerabilities_not_found,
                'vulnerabilities_unexpected': vulnerabilities_unexpected,
                'failed_agents': failed_agents,
                'result': result
            }


def expected_vulnerabilities_index(vulnerabilities, expected_vulnerabilities):
    expected_found_comparision = compare_expected_found_vulnerabilities(vulnerabilities,
                                                                        expected_vulnerabilities)

    return expected_found_comparision['result']


def compare_expected_found_vulnerabilities_alerts(vulnerabilities, expected_vulnerabilities):
    result = True
    vulnerabilities_affected_not_found = {}
    vulnerabilities_mitigated_not_found = {}

    failed_agents = []

    vulnerabilities_present = vulnerabilities.get('affected', {})
    vulnerabilities_absent = vulnerabilities.get('mitigated', {})
    expected_vulnerabilities_affected = expected_vulnerabilities.get('affected', {})
    expected_vulnerabilities_mitigated = expected_vulnerabilities.get('mitigated', {})

    for agent, vulnerabilities in expected_vulnerabilities_affected.items():
        for vulnerability in vulnerabilities:
            if vulnerability not in vulnerabilities_present.get(agent):
                if agent not in vulnerabilities_affected_not_found:
                    vulnerabilities_affected_not_found[agent] = []
                    failed_agents.append(agent)

                vulnerabilities_affected_not_found[agent].append(vulnerability)
                result = False

    for agent, vulnerabilities in expected_vulnerabilities_mitigated.items():
        for vulnerability in vulnerabilities:
            if vulnerability not in vulnerabilities_absent.get(agent):
                if agent not in vulnerabilities_mitigated_not_found:
                    vulnerabilities_mitigated_not_found[agent] = []
                    failed_agents.append(agent)

                vulnerabilities_mitigated_not_found[agent].append(vulnerability)
                result = False

    if not result:
        logging.critical(f"Vulnerabilities affected not found: {vulnerabilities_affected_not_found}")
        logging.critical(f"Vulnerabilities mitigated not found: {vulnerabilities_mitigated_not_found}")

    return {
                'vulnerabilities_affected_not_found': vulnerabilities_affected_not_found,
                'vulnerabilities_mitigated_not_found': vulnerabilities_mitigated_not_found,
                'failed_agents': failed_agents,
                'result': result
            }


def expected_vulnerability_alerts(vulnerabilities, expected_vulnerabilities):

    expected_found_comparision = compare_expected_found_vulnerabilities_alerts(vulnerabilities,
                                                                               expected_vulnerabilities)
    return expected_found_comparision['result']


equals = lambda x, y: x == y


def equals_but_not_empty(x, y):
    return equals(x, y) and not empty(x)


empty = lambda x: len(x) == 0

no_errors = lambda x: all(
    not any(x[host][level] for level in ["ERROR", "CRITICAL", "WARNING"])
    for host in x
)
