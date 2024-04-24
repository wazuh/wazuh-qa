import yaml


def load_test_cases(file_path):
    with open(file_path, "r") as cases_file:
        cases = yaml.load(cases_file, Loader=yaml.FullLoader)
    return cases if cases else []


def extract_case_info(cases):
    return [
        (case.get("preconditions"), case.get("body"), case.get("teardown"))
        for case in cases
    ]


def get_case_ids(cases):
    return [case["id"] for case in cases]
