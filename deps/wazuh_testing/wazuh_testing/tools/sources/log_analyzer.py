import pandas as pd
import os
import re
from itertools import groupby
from mmap import mmap, ACCESS_READ
import numpy as np
from re import compile, MULTILINE
from datetime import datetime

class LogAnalyzer:
    """
    """
    def __init__(self, artifact_path):
        if not os.path.isdir(artifact_path):
            raise ValueError

        self.artifact_path = artifact_path

        agents_path = os.path.join(artifact_path, 'agents')
        managers_path = os.path.join(artifact_path, 'managers')
        master_path = os.path.join(artifact_path, 'managers', 'master')
        worker_path = os.path.join(artifact_path, 'managers', 'worker')

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

    def get_instances_artifacts(self, component="agents", hosts_regex=".*"):
        # Get list of agents (directories), get all agents that fit that regex
        artifacts_files = []
        if component == 'all':
            artifacts_files += self.get_instances_artifacts('managers', hosts_regex)
            artifacts_files += self.get_instances_artifacts('agents', hosts_regex)

        elif component == 'managers':
            artifacts_files += self.get_instances_artifacts('master', hosts_regex)
            artifacts_files += self.get_instances_artifacts('workers', hosts_regex)
        else:
            try:
                artifact_path = self.component_path[component]
                artifacts_files = [{"name": f, "path": os.path.join(artifact_path, f)} for f in os.listdir(artifact_path) if
                    re.match(rf'{hosts_regex}', f)]
            except Exception as e:
                pass
                # print("ERROR:" + str(e))
                # print(f"Ignoring {component} - Artifact not found")
        return artifacts_files

    def get_instances_logs(self, log='ossec.log', component="agents", hosts_regex=".*"):
        # Get list of agents (directories), get all agents that fit that regex
        files = self.get_instances_artifacts(component, hosts_regex)
        for file in files:
            file['logs'] = {}
            if log == 'all':
                log_files_to_get = self.get_instance_all_log_files(file['name'])
            else:
                log_files_to_get = [log]
            for log_get in log_files_to_get:
                general_path = os.path.join(file['path'], 'logs')
                file['logs'][log_get] = os.path.join(general_path, log_get)
            del file['path']
        return files

    def get_instance_all_log_files(self, hostname):
        # Get list of agents (directories), get all agents that fit that regex
        files = self.get_instances_artifacts('all', hostname)
        files = os.path.join(files[0]['path'], 'logs')
        host_log_list = [log for log in os.listdir(files)]
        return host_log_list

    def get_instances_process_metrics(self, process='wazuh-agentd', component="agent", hosts_regex='.*'):
        files = self.get_instances_artifacts(component, hosts_regex=hosts_regex)
        for file in files:
            file.update((k, os.path.join(v, 'data', 'binaries', process + '.csv')) for k, v in file.items())
        return files

    def get_instances_stats(self, stat='wazuh-agentd', component="agent", hosts_regex='.*'):
        files = self.get_instances_artifacts(component, hosts_regex)
        for file in files:
            file['path'] = os.path.join(file['path'], 'data', 'stats', stat + '_stats.csv')
        return files

    def make_report(self):
        report = {}
        # Logs analysis
        report['metadata'] = {'n_agents': self.n_agents, 'n_workers': self.n_workers}
        report['agents'] = self.analyze_errors_logs(log='all', component='agents')
        report['managers'] = self.analyze_errors_logs(log='all', component='managers')
        report['agents']['wazuh-agentd'] = self.analyze_agentd()
        report['managers']['wazuh-remoted'] = self.analyze_remoted_statistics()
        report['managers']['wazuh-remoted'] = {**report['managers']['wazuh-remoted'], **self.keep_alive_log_parser()}

        return report

    def check_errors(self, log_path, type='error'):
        with open(log_path) as f:
            error_lines = []
            try:
                s = mmap(f.fileno(), 0, access=ACCESS_READ)
                regex_line = bytes(f"(^.*?{type}.*?$)", encoding='utf8')
                error_lines = re.findall(regex_line, s, flags=re.MULTILINE | re.IGNORECASE)
                if error_lines:
                    error_lines = [error.decode(encoding='utf8') for error in error_lines]
            except Exception as e:
                pass
                #print(f"Error reading {log_path} - Ignored")

            return error_lines

    def analyze_errors_logs(self, log, component='agents', hosts_regex='.*'):
        error_codes = ['warning', 'error', 'critical']
        error_dict = {'criticals': [], 'errors': [], 'warnings': []}

        log_list = self.get_instances_logs(log, component, hosts_regex)
        for type in error_codes:
            for host in log_list:
                error_list_host = []
                for name, path in host['logs'].items():
                    if os.path.exists(path):
                        agent_error = self.check_errors(path, type)
                        if agent_error:
                            error_list_host += [f"[{name}] " + agent_error_line for agent_error_line in agent_error]
                if error_list_host:
                    error_dict[type+'s'] += [{host['name']:  error_list_host}]
        return error_dict

    def analyze_remote_logs(self, log, component='master', hosts_regex='.*'):
        pass

    def analyze_metric(self, process, component, hosts_regex='.*'):
        return {}

    def analyze_agentd(self, component='agents', hosts_regex='.*'):
        agentd_report = self.analyze_agentd_statistics(component, hosts_regex)
        agentd_report['metrics'] = self.analyze_metric(process='wazuh-agentd', component=component)
        return agentd_report


    def calculate_values(self, stat, fields, component, hosts_regex='.*'):
        stats = self.get_instances_stats(stat=stat, component=component, hosts_regex=hosts_regex)
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

                mean_fields['max_' + field] = int(max) if not mean_fields['max_' + field] or max >  mean_fields['max_' + field] else int(mean_fields['max_' + field])
                mean_fields['min_' + field] = int(min) if  not mean_fields['min_' + field] or  min <  mean_fields['min_' + field] else int(mean_fields['min_' + field])

                mean_fields['max_mean_' + field] = int(mean) if mean >  mean_fields['max_mean_' + field] else int(mean_fields['max_mean_' + field])
                mean_fields['min_mean_' + field] = int(mean) if mean <  mean_fields['min_mean_' + field] else int(mean_fields['min_mean_' + field])

                mean_fields['mean_' + field] += int(mean)


                reg_cof = int(np.polyfit(range(len(dataframe)), list(dataframe[field]), 1)[0])
                mean_fields['mean_reg_cof_' + field] += reg_cof
                mean_fields['max_reg_cof_' + field] = int(reg_cof) if not mean_fields['max_reg_cof_' + field] or reg_cof >  mean_fields['max_reg_cof_' + field] else int(mean_fields['max_reg_cof_' + field])
                mean_fields['min_reg_cof_' + field] = int(reg_cof) if  not mean_fields['min_reg_cof_' + field] or reg_cof <  mean_fields['min_reg_cof_' + field] else int(mean_fields['min_reg_cof_' + field])

        for field in fields:
            mean_fields['mean_' + field] = mean_fields['mean_' + field] / n_stats
            mean_fields['mean_reg_cof_' + field] = mean_fields['mean_reg_cof_' + field] / n_stats
        return mean_fields


    def analyze_agentd_statistics(self, component='agents', hosts_regex='.*'):
        # Status
        agentd_stats = self.get_instances_stats(stat='wazuh-agentd', component=component, hosts_regex='.*')
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
        logs_files = self.get_instances_logs(component=component, hosts_regex=hosts_regex)
        keep_alives= {}
        for log_file in logs_files:
            regex = compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) wazuh\-remoted.* reading '(.*)\|(.*)\|(.*)\|(.*)\|(.* \[.*\].*)\n(.*)\n.*:(\d+\.\d+\.\d+\.\d+)", MULTILINE)
            print(log_file)
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
                        keep_alives[match.group(3)]["mean_difference"] +=  abs(recent_keep_alive_datetime - last_keep_alive_datetime).seconds
                        keep_alives[match.group(3)]["last_keep_alive"] = match.group(1)

                keep_alives[match.group(3)]["mean_difference"] = keep_alives[match.group(3)]["mean_difference"]/keep_alives[match.group(3)]["n_keep_alive"]
            print(keep_alives)
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
                last_keep_alive = datetime.strptime(keep_alives[agent]['last_keep_alive'], '%Y/%m/%d %H:%M:%S')
                keep_alives[agent] =  {**keep_alives[agent], **{'remainder': abs(last_message - last_keep_alive ).seconds }}

        ret = {'keep_alives': keep_alives}
        return ret