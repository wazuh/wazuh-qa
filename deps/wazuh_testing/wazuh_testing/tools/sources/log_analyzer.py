import os
import re

import pandas as pd
import numpy as np

from itertools import groupby
from mmap import mmap, ACCESS_READ
from re import compile, MULTILINE
from datetime import datetime


class LogAnalyzer:
    error_codes = ['warning', 'error', 'critical']

    @staticmethod
    def findall_regex_line(lines, regex, flags):
        error_lines = re.findall(regex, fr"{lines}", flags=flags)
        error_lines = [error.decode(encoding='utf8') for error in error_lines] if error_lines else []
        return error_lines

    @staticmethod
    def get_error_log_file(log_path, type='error'):
        error_lines = []
        if os.path.getsize(log_path) != 0:
            with open(log_path) as f:
                log_file_content = mmap(f.fileno(), 0, access=ACCESS_READ)

                error_lines = LogAnalyzer.findall_regex_line(lines=log_file_content, regex=f"(^.*?{type}\:.*?$)",
                                                             flags=re.MULTILINE | re.IGNORECASE)
        return error_lines

    @staticmethod
    def get_error_logs_hosts(log_dict):
        error_dict = {'critical': [], 'error': [], 'warning': []}
        for type in LogAnalyzer.error_codes:
            for host_log in log_dict:
                error_list_host = []
                for host_name, log_path in host_log['logs'].items():
                    if os.path.exists(log_path):
                        agent_error = LogAnalyzer.get_error_log_file(log_path, type)
                        if agent_error:
                            error_list_host += \
                                              [f"[{host_name}] " + agent_error_line for agent_error_line in agent_error]
                if error_list_host:
                    error_dict[type] += [{host_log['name']:  error_list_host}]
        return error_dict


class StatisticsAnalyzer:
    pass


class ReportGenerator:
    def __init__(self, artifact_path):

        if os.path.isdir(artifact_path):
            self.artifact_path = artifact_path

            agents_path = os.path.join(artifact_path, 'agents')
            managers_path = os.path.join(artifact_path, 'managers')

            master_path = os.path.join(artifact_path, 'managers', 'master')
            worker_path = os.path.join(artifact_path, 'managers', 'worker')

            if not (os.path.isdir(agents_path) or os.path.isdir(managers_path) or os.path.isdir(master_path)):
                print("ERROR: The artifact file structure should follow this scheme")
                print("""
                ├── agents
                │   └── agent1
                │       ├── data
                │       │   ├── binaries
                │       │   └── stats
                │       └── logs
                └── managers
                    ├── master
                    │   └── master-instance
                    │       ├── data
                    │       │   ├── binaries
                    │       │   └── stats
                    │       └── logs
                    └── workers
                        └── worker1
                            ├── data
                            │   ├── binaries
                            │   └── stats
                            └── logs
                """)
                raise ValueError

        self.component_path = {
            'agents': agents_path,
            'managers': managers_path,
            'master': master_path,
            'workers': worker_path
        }

        if os.path.isdir(worker_path):
            self.n_workers = len(os.listdir(worker_path))
            self.cluster_environment = True
        else:
            self.n_workers = 0
            self.cluster_environment = False

        self.n_agents = len(os.listdir(agents_path))

    def get_instances_artifacts(self, component, hosts_regex=".*"):
        artifacts_files = []
        if component == 'all':
            artifacts_files += self.get_instances_artifacts('managers', hosts_regex)
            artifacts_files += self.get_instances_artifacts('agents', hosts_regex)
        elif component == 'managers':
            artifacts_files += self.get_instances_artifacts('master', hosts_regex)
            if self.cluster_environment:
                artifacts_files += self.get_instances_artifacts('workers', hosts_regex)
        else:
            artifact_path = self.component_path[component]
            artifacts_files = [{"name": f, "path": os.path.join(artifact_path, f)}
                               for f in os.listdir(artifact_path) if re.match(rf'{hosts_regex}', f)]
        return artifacts_files

    def get_instance_all_log_files(self, hostname):
        files = os.path.join(self.get_instances_artifacts('all', hostname)[0]['path'], 'logs')
        host_log_list = [log for log in os.listdir(files)]
        return host_log_list

    def get_instances_logs(self, log, component, hosts_regex=".*"):
        artifacts_paths = self.get_instances_artifacts(component, hosts_regex)
        for host_artifact_path in artifacts_paths:
            host_artifact_path['logs'] = {}
            log_files = self.get_instance_all_log_files(host_artifact_path['name']) if log == 'all' else [log]

            for log_file in log_files:
                general_path = os.path.join(host_artifact_path['path'], 'logs')
                host_artifact_path['logs'][log_file] = os.path.join(general_path, log_file)
            del host_artifact_path['path']

        return artifacts_paths

    def get_instances_process_metrics(self, process, component, hosts_regex='.*'):
        files = self.get_instances_artifacts(component, hosts_regex=hosts_regex)
        for file in files:
            file.update((k, os.path.join(v, 'data', 'binaries', process + '.csv')) for k, v in file.items())
        return files

    def get_instances_stats(self, statistic, component, hosts_regex='.*'):
        files = self.get_instances_artifacts(component, hosts_regex)
        for file in files:
            file['path'] = os.path.join(file['path'], 'data', 'stats', statistic + '_stats.csv')
        return files

    def analyze_agentd(self, component='agents', hosts_regex='.*'):
        agentd_report = self.analyze_agentd_statistics(component, hosts_regex)
        return agentd_report

    def calculate_values(self, statistic, fields, component, hosts_regex='.*'):
        stats = self.get_instances_stats(statistic=statistic, component=component, hosts_regex=hosts_regex)
        n_stats = len(stats)
        mean_fields = {}

        for field in fields:
            mean_fields['mean_' + field] = 0
            mean_fields['max_mean_' + field] = 0
            mean_fields['min_mean_' + field] = 0

            mean_fields['min_' + field] = None
            mean_fields['max_' + field] = None

            mean_fields['mean_reg_cof_' + field] = 0
            mean_fields['max_reg_cof_' + field] = None
            mean_fields['min_reg_cof_' + field] = None

        dataframe = pd.DataFrame()

        for statistic in stats:
            for field in fields:
                dataframe = pd.read_csv(statistic['path'])
                mean = dataframe[field].mean()

                max = dataframe[field].max()
                min = dataframe[field].min()

                mean_fields['max_' + field] = int(max) if not mean_fields['max_' + field] or max > \
                                                              mean_fields['max_' + field] else int(mean_fields['max_' + field])

                mean_fields['min_' + field] = int(min) if not mean_fields['min_' + field] or min < \
                                                              mean_fields['min_' + field] else int(mean_fields['min_' + field])

                mean_fields['max_mean_' + field] = int(mean) if mean > mean_fields['max_mean_' + field] else int(mean_fields['max_mean_' + field])
                mean_fields['min_mean_' + field] = int(mean) if mean < mean_fields['min_mean_' + field] else int(mean_fields['min_mean_' + field])

                mean_fields['mean_' + field] += int(mean)

                reg_cof = int(np.polyfit(range(len(dataframe)), list(dataframe[field]), 1)[0])
                mean_fields['mean_reg_cof_' + field] += reg_cof
                mean_fields['max_reg_cof_' + field] = int(reg_cof) if not mean_fields['max_reg_cof_' + field] or reg_cof >  mean_fields['max_reg_cof_' + field] else int(mean_fields['max_reg_cof_' + field])
                mean_fields['min_reg_cof_' + field] = int(reg_cof) if not mean_fields['min_reg_cof_' + field] or reg_cof <  mean_fields['min_reg_cof_' + field] else int(mean_fields['min_reg_cof_' + field])

        for field in fields:
            mean_fields['mean_' + field] = mean_fields['mean_' + field] / n_stats
            mean_fields['mean_reg_cof_' + field] = mean_fields['mean_reg_cof_' + field] / n_stats
        return mean_fields

    def analyze_agentd_statistics(self, component='agents', hosts_regex='.*'):
        # Status
        agentd_stats = self.get_instances_stats(statistic='wazuh-agentd', component=component, hosts_regex='.*')
        n_stats = len(agentd_stats)
        agentd_report = {
            "begin_status": {"connected": 0, "pending": 0, "disconnected": 0},
            "end_status": {"connected": 0, "pending": 0, "disconnected": 0},
            "ever_disconnected": 0,
            "ever_connected": 0,
            "ever_pending": 0,

            "mean_status_change_count": 0,
            "max_status_change_count": 0,

            "max_diff_ack_keep_alive": 0,
            "mean_diff_ack_keep_alive": 0,
            "metrics": {}
        }
        if n_stats == 1:
            agentd_report['begin'] = {}
            agentd_report['end'] = {}

        status_dataframe = pd.DataFrame()
        for agentd_stat in agentd_stats:
            agent_dataframe = pd.read_csv(agentd_stat['path'])
            # Status
            status_dataframe = agent_dataframe['status']

            # Begin and end
            begin_status_value = status_dataframe.iloc[0]
            end_status_value = status_dataframe.iloc[len(status_dataframe.index) - 1]
            agentd_report["begin_status"][begin_status_value] += 1
            agentd_report["end_status"][end_status_value] += 1

            agent_status_count = status_dataframe.value_counts().to_dict()
            if 'pending' in agent_status_count:
                agentd_report["ever_pending"] += 1

            if 'connected' in agent_status_count:
                agentd_report["ever_connected"] += 1

            if 'disconnected' in agent_status_count:
                agentd_report["ever_disconnected"] += 1

            status_change_count = len([x[0] for x in groupby(agent_status_count)]) - 1
            agentd_report['mean_status_change_count'] += status_change_count

            if status_change_count > agentd_report['max_status_change_count']:
                agentd_report['max_status_change_count'] = status_change_count

            # ACK - KEEP ALIVE
            diff = (abs(pd.to_datetime(agent_dataframe['last_keepalive']) -
                    pd.to_datetime(agent_dataframe['last_ack']))).astype('timedelta64[s]')

            agentd_report["mean_diff_ack_keep_alive"] += diff.mean()
            max = diff.max()

            if max > agentd_report["max_diff_ack_keep_alive"]:
                agentd_report["max_diff_ack_keep_alive"] = max
        agentd_report['mean_status_change_count'] /= n_stats

        agentd_report = {**agentd_report, **(self.calculate_values('wazuh-agentd', 
                                         ['msg_sent','msg_count', 'msg_buffer'], 'agents'))}
        return agentd_report

    def analyze_remoted_statistics(self, component='managers', hosts_regex='.*'):

        remoted_report = self.calculate_values('wazuh-remoted', 
                                         ['queue_size', 'total_queue_size', 'tcp_sessions', 'evt_count', 
                                         'ctrl_msg_count', 'discarded_count', 'queued_msgs', 'sent_bytes', 
                                         'recv_bytes', 'dequeued_after_close'], 'managers')
        return remoted_report

    def keep_alive_log_parser(self, component='master', hosts_regex='.*'):
        logs_files = self.get_instances_logs(log='ossec.log', component=component, hosts_regex=hosts_regex)
        keep_alives = {}
        for log_file in logs_files:
            regex = compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) wazuh\-remoted.* reading '(.*)\|(.*)\|(.*)\|(.*)\|(.* \[.*\].*)\n(.*)\n.*:(\d+\.\d+\.\d+\.\d+)", MULTILINE)
            with open(log_file['logs']['ossec.log']) as log:
                for match in regex.finditer(log.read()):
                    if match.group(3) not in keep_alives:
                        keep_alives[match.group(3)] = {"n_keep_alive": 1, "max_difference": 0, "mean_difference": 0, "last_keep_alive": match.group(1), "first_keep_alive": match.group(1) }
                    else:
                        keep_alives[match.group(3)]["n_keep_alive"] += 1

                        last_keep_alive_datetime = datetime.strptime(keep_alives[match.group(3)]["last_keep_alive"], '%Y/%m/%d %H:%M:%S')
                        recent_keep_alive_datetime = datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S')
                        if keep_alives[match.group(3)]["max_difference"] < abs(recent_keep_alive_datetime - last_keep_alive_datetime).seconds:
                            keep_alives[match.group(3)]["max_difference"] = abs(recent_keep_alive_datetime - last_keep_alive_datetime).seconds
                        keep_alives[match.group(3)]["mean_difference"] += abs(recent_keep_alive_datetime - last_keep_alive_datetime).seconds
                        keep_alives[match.group(3)]["last_keep_alive"] = match.group(1)

            for key in keep_alives.keys():
                keep_alives[key]["mean_difference"] = keep_alives[key]["mean_difference"]/keep_alives[key]["n_keep_alive"]
            remainder = None
            with open(log_file['logs']['ossec.log']) as log:
                log_lines = log.readlines()
                for line in reversed(log_lines):
                    last_log_line = line
                    remainder = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*", last_log_line)
                    if remainder:
                        remainder = remainder.group(1)
                        break
            last_message = datetime.strptime(remainder, '%Y/%m/%d %H:%M:%S')

            for agent in keep_alives.keys():
                print(agent)
                last_keep_alive = datetime.strptime(keep_alives[agent]['last_keep_alive'], '%Y/%m/%d %H:%M:%S')
                keep_alives[agent] = {**keep_alives[agent], **{'remainder': abs(last_message - last_keep_alive ).seconds }}
        ret = {'keep_alives': keep_alives}
        return ret

    def make_report(self):
        report = {}

        report['metadata'] = {'n_agents': self.n_agents, 'n_workers': self.n_workers}

        report['agents'] = LogAnalyzer.get_error_logs_hosts(log_dict=self.get_instances_logs(log='all', component='agents'))
        report['managers'] = LogAnalyzer.get_error_logs_hosts(log_dict=self.get_instances_logs(log='all', component='managers'))

        report['agents']['wazuh-agentd'] = self.analyze_agentd()
        report['managers']['wazuh-remoted'] = self.analyze_remoted_statistics()
        report['managers']['wazuh-remoted'] = {**report['managers']['wazuh-remoted'], **self.keep_alive_log_parser()}

        return report