import logging 


def validate_operation_results(global_operation_results: dict) -> bool:
    logging.critical(global_operation_results)
    for _, task_results in global_operation_results.items():
        for operation_result in task_results:
            operation = list(operation_result.keys())[0]
            operation_success = operation_result[operation]["success"]
            if not operation_success:
                logging.critical(f"Operation {operation} failed")
                return False
    return True


def validate_vulnerabilities_results(global_operation_results: dict):
    check_vulnerabilities_operations = [
        "install_package",
        "remove_package",
        "update_package",
    ]
    expected_vulnerabilities_found = True

    for agent, agent_operation_results in global_operation_results.items():
        for task_lists_results in agent_operation_results:
            for task, result in task_lists_results.items():
                task_result = True

                vulnerabilities = result.get("vulnerabilities", {})
                index_vulnerabilities = vulnerabilities.get("index_vulnerabilities", [])
                alerts_vulnerabilities = vulnerabilities.get(
                    "alerts_vulnerabilities", []
                )
                mitigated_vulnerabilities = vulnerabilities.get(
                    "mitigated_vulnerabilities", []
                )

                expected_vulnerabilities = result.get("expected_vulnerabilities", {})
                expected_index = expected_vulnerabilities.get("states", [])
                expected_alerts = expected_vulnerabilities.get("alerts", [])
                if task in check_vulnerabilities_operations:
                    # Check vulnerabilities
                    if task == "update_package":
                        continue
                    elif task == "remove_package":
                        if len(index_vulnerabilities) != 0:
                            logging.critical(
                                "Vulnerabilities differs in states index"
                                "from expected in {agent} for task {task}"
                            )
                            logging.critical(f"Expected: {expected_index}")
                            logging.critical(f"Found: {index_vulnerabilities}")
                            task_result = False
                        if mitigated_vulnerabilities != expected_alerts:
                            logging.critical(
                                "Vulnerabilities differs in states index from"
                                f"expected in {agent} for task {task}"
                            )
                            logging.critical(f"Expected: {expected_index}")
                            logging.critical(f"Found: {index_vulnerabilities}")
                            task_result = False
                    else:
                        if task == "install_package":
                            if index_vulnerabilities != expected_index:
                                logging.critical(
                                    "Vulnerabilities differs in states index from"
                                    f"expected in {agent} for task {task}"
                                )
                                logging.critical(f"Expected: {expected_index}")
                                logging.critical(f"Found: {index_vulnerabilities}")
                                task_result = False

                            if alerts_vulnerabilities != expected_alerts:
                                logging.critical(
                                    "Vulnerabilities Alerts differs from expected"
                                    f"in {agent} for task {task}"
                                )
                                logging.critical(f"Expected: {expected_alerts}")
                                logging.critical(f"Found: {alerts_vulnerabilities}")
                                task_result = False

                    if not task_result:
                        expected_vulnerabilities_found = False

    return expected_vulnerabilities_found

equals = lambda x, y: x == y


def equals_but_not_empty(x, y):
    return equals(x, y) and not empty(x)


empty = lambda x: len(x) == 0
no_errors = lambda x: all(
    not any(x[host][level] for level in ["ERROR", "CRITICAL", "WARNING"])
    for host in x
)

