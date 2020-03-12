import json

data = {}
data['json_verification'] = {
    'result': '',
    'scenarios': {}
}

common_ = {
    'result': '',
    'hosts': {},
}

scenario_vars = {
        "result": "",
        'added': common_,
        'deleted': common_,
        'modified': common_
}

data['json_verification']['scenarios']['201_default_scenario'] = scenario_vars

host_vars = {
        'host_os': '',
        'host_arch': '',
        'result': '',
        'expected_alerts': '',
        'received_alerts': '',
        'missing_alerts': '',
        'missing_paths': [],
}

data['json_verification']['scenarios']['201_default_scenario']['added']['hosts']['10.0.0.1'] = host_vars


with open('results.json', 'w') as outfile:
    json.dump(data, outfile)
