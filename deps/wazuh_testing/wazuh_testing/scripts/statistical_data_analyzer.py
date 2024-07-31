import argparse
import os
import sys
import pandas as pd
from prettytable import PrettyTable
from scipy.stats import ttest_ind, levene, f_oneway

STATS_MAPPING = {
    'cpu': 'CPU(%)',
    'memory': 'RSS(KB)',
    'virtual_memory': 'VMS(KB)',
    'file_descriptor': 'FD',
    'read_ops': 'Read_Ops',
    'write_ops': 'Write_Ops',
    'disk_read': 'Disk_Read(B)',
    'disk_written': 'Disk_Written(B)',    
    'disk_usage': 'Disk(%)',
    'uss': 'USS(KB)',
    'pss': 'PSS(KB)',
    'swap': 'SWAP(KB)',
}

STATISTICS_LIST = ['Mean', 'Median', 'Max value', 'Min value', 'Standard deviation', 'Variance']

class DataLoader:
    """
    """
    def __init__(self, baseline_path, datasource_path):
        """
        """
        self.baseline_path = baseline_path
        self.datasource_path = datasource_path
        self.validate_paths()
        self.baseline = self.load_dataframe(baseline_path)
        self.datasource = self.load_dataframe(datasource_path)
        self.metrics = self.load_metrics()

    def validate_paths(self):
        """
        """
        if not os.path.exists(self.baseline_path) or not os.path.exists(self.datasource_path):
            raise ValueError(f"One or both of the provided files do not exist")   

    def load_dataframe(path):
        """
        """
        dataframe = pd.read_csv(path)
        if len(dataframe) == 0:
            raise ValueError(f"The file {path} has not data rows or it has not CSV format")
        
    def load_metrics(self):
        """
        """
        metrics = [col for col in self.baseline.columns if pd.api.types.is_numeric_dtype(self.baseline[col])]
        return metrics


class StatisticalComparator:
    """
    """
    def __init__(self, dataframe, metrics):
        """
        """
        self.dataframe = dataframe
        self.metrics = metrics
        

    def calculate_basic_statistics(self):
        """Calculate basic statistics on the Dataframe for comparison.
        
        Args:
            dataframe: Dataframe on which to calculate the statistics.
        
        Returns:
            results: dict that contains all the statistics calculate for the dataframe
        """
        results = {}
        daemons = self.dataframe['Daemon'].unique()

        for daemon in daemons:
            daemon_data = self.dataframe[self.dataframe['Daemon'] == daemon]
            stats = []
            for metric in self.metrics.values():
                stat = {
                    'Metric': metric,
                    'Mean': round(float(daemon_data[metric].mean()), 2),
                    'Median': round(float(daemon_data[metric].median()), 2),
                    'Max value': round(float(daemon_data[metric].max()), 2),
                    'Min value': round(float(daemon_data[metric].min()), 2),
                    'Standard deviation': round(float(daemon_data[metric].std()), 2),
                    'Variance': round(float(daemon_data[metric].var()), 2)
                }
                stats.append(stat)
            results[daemon] = stats
        
        return results


    def comparison_basic_statistics(baseline, datasource, daemon, value, stat, threshold):
        """Compares the percentage change in a given statistic between the two data sets, and 
        returns whether there is a significant change based on a threshold value.

        Args:
            baseline: Dataframe with the baseline data.
            datasource: Dataframe with the data source.
            daemon: concrete daemon on which to obtain the values.
            value: metric from which the statistics to be compared are obtained.
            stat: concrete statistic to be compared.
            threshold: Threshold for comparison. If not specified, default is 5%.

        Returns:
            discrepancie: If the percentage difference is greater than the threshold,
            it returns 1, otherwise it returns 0.
        """
        baseline_statistics = calculate_basic_statistics(baseline)
        dataframe_statistics = calculate_basic_statistics(datasource)
        discrepancy = 0
        baseline_value = get_stat_value(baseline_statistics[daemon], value, stat)
        dataframe_value = get_stat_value(dataframe_statistics[daemon], value, stat)

        if baseline_value != 0:
            diff = abs(baseline_value - dataframe_value) / baseline_value
        else:
            diff = abs(baseline_value - dataframe_value)
        
        if diff >= threshold:
            discrepancy = 1
        
        return discrepancy





def get_parameters():
    """Get and process script parameters.
    
    Returns:
        argparse.Namespace: script parameters.
    """
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-b', '--baseline', metavar='<file>', type=str, action='store',
                            help='Baseline file to compare', required=True, dest='baseline_data')

    arg_parser.add_argument('-f', '--file', metavar='<file>', type=str, action='store',
                            help='Data file to compare', required=True, dest='data_source')
    
    return arg_parser.parse_args()


def validate_parameters(parameters, datasource):
    """Validate the input parameters

    Args:
        parameters (argparse.Namespace): script parameters.
        datframe: data frame obtained from the data source file
    """
    # Check that the file exists
    if not os.path.exists(parameters.baseline_data) or not os.path.exists(parameters.data_source):
        print(f"The files provided do not exist")
        sys.exit(1)
    
    # Check that the source file has more than 0 rows
    dataframe = load_dataframe(datasource)
    data_length = len(dataframe)    
    if data_length == 0:
        print(f"The source '{dataframe}' has not data rows or it has not CSV format")
        sys.exit(1)


def load_dataframe(datasource):
    """Read the CSV and convert it to dataframe

    Args:
        datasource: data source file path.

    Returns:
        DataFrame: dataframe object.
    """
    return pd.read_csv(datasource)


def calculate_basic_statistics(dataframe):
    """Calculate basic statistics on the data source file for comparison.
    
    Args:
        dataframe: Dataframe on which to calculate the statistics.
    
    Returns:
        results: dict that contains all the statistics calculate for the dataframe
    """
    results = {}
    daemons = dataframe['Daemon'].unique()

    for daemon in daemons:
        daemon_data = dataframe[dataframe['Daemon'] == daemon]
        stats = []
        for value in STATS_MAPPING.values():
            stat = {
                'Metric': value,
                'Mean': round(float(daemon_data[value].mean()), 2),
                'Median': round(float(daemon_data[value].median()), 2),
                'Max value': round(float(daemon_data[value].max()), 2),
                'Min value': round(float(daemon_data[value].min()), 2),
                'Standard deviation': round(float(daemon_data[value].std()), 2),
                'Variance': round(float(daemon_data[value].var()), 2)
            }
            stats.append(stat)
        results[daemon] = stats
    
    return results


def get_stat_value(metrics, value, stat):
    """Checks if the metric is correct to return the specific statistic.

    Args:
        metrics: the metrics of a specific daemon.
        value: value of this metric.
        stat: statistics of this metric to be returned.
    
    Returns:
        stat_value: value of the statistic desired.
    """
    for metric in metrics:
        if metric['Metric'] == value:
            return metric[stat]





def t_student_test(baseline, datasource, value):
    """Function that performs the statistical analysis using the t-student test.

    Args:
        baseline: Dataframe with the baseline data.
        datasource: Dataframe with the data source.
        value: metric on which the test is performed

    Returns:
        t_p_value: p value returned by the t-student test.
    """
    ref_values = baseline[value].dropna()
    new_values = datasource[value].dropna() 

    t_stat, t_p_value = ttest_ind(ref_values, new_values, equal_var=False)

    return t_p_value  


def t_levene_test(baseline, datasource, value):
    """Function that performs the statistical analysis using the Levene test.

    Args:
        baseline: Dataframe with the baseline data.
        datasource: Dataframe with the data source.
        value: metric on which the test is performed.
    
    Returns:
        l_p_value: p value returned by the Levene test.
    """
    ref_values = baseline[value].dropna()
    new_values = datasource[value].dropna() 

    l_stat, l_p_value = levene(ref_values, new_values)

    return l_p_value


def t_anova_test(baseline, datasource, value):
    """Function that performs the statistical analysis using the ANOVA test.

    Args:
        baseline: Dataframe with the baseline data.
        datasource: Dataframe with the data source.
        value: metric on which the test is performed.

    Returns:
        a_p_value: p value returned by the ANOVA test.
    """
    ref_values = baseline[value].dropna()
    new_values = datasource[value].dropna() 

    a_stat, a_p_value = f_oneway(ref_values, new_values)

    return a_p_value


def data_comparison_test(baseline, datasource, percentage=95):
    """Calculate statistics values for t-Student, Levene tests and ANOVA test, and shows the results. 
    Also, it detect if there are significant difference detected between both values.

    Args:
        baseline: file with the baseline values.
        datasource: file with the values to compare.
        percentage: percentage of confidence level.
    """
    dataframe_ref = load_dataframe(baseline)
    dataframe = load_dataframe(datasource)
    alpha = float((100 - percentage) / 100)
    daemons = dataframe_ref['Daemon'].unique()

    for daemon in daemons:
        print(f"\nDaemon: {daemon}\n")
        ref_daemon_data = dataframe_ref[dataframe_ref['Daemon'] == daemon]
        new_daemon_data = dataframe[dataframe['Daemon'] == daemon]

        for value in STATS_MAPPING.values():
            ref_values = ref_daemon_data[value].dropna()
            new_values = new_daemon_data[value].dropna()

            # t-Student
            t_stat, t_p_value = ttest_ind(ref_values, new_values, equal_var=False)
            # Levene
            l_stat, l_p_value = levene(ref_values, new_values)
            # Anova
            a_stat, a_p_value = f_oneway(ref_values, new_values)

            print(f"\nMetric '{value}':")
            print(f"    - t-Student Test: t-Statistic={t_stat}, p-value={t_p_value}")
            print(f"    - Levene's Test: Statistic={l_stat}, p-value={l_p_value}")
            print(f"    - ANOVA's Test: Statistic={a_stat}, p-value={a_p_value}")

            if t_p_value < alpha:
                print(f"\n  Significant difference detected in '{value}' with {percentage}% confidence (t-Test).")
            if l_p_value < alpha:
                print(f"\n  Variance difference detected in '{value}' with {percentage}% confidence (Levene's Test).")
            if a_p_value < alpha:
                print(f"\n  Means difference detected in '{value}' with {percentage}% confidence (ANOVA's Test).")
        print("\n")


def print_dataframes_stats(baseline, datasource):
    """Print a PrettyTable with the statistics for each daemon and metric.

    Args:
        baseline: Dataframe with the baseline values.
        datasource: Dataframe with the values to compare.
    """
    daemons = baseline['Daemon'].unique()
    output = ""

    for daemon in daemons:
        baseline_data = baseline[baseline['Daemon'] == daemon]
        datasource_data = datasource[datasource['Daemon'] == daemon]

        for value in STATS_MAPPING.values():
            table = PrettyTable()
            table.title = daemon + " - " + value
            table.field_names = ['Name', 'Mean', 'Max value', 'Min value', 'Standard deviation', 'Variance']
            table.add_row(["Baseline", round(baseline_data[value].mean(), 2),
                        baseline_data[value].max(), baseline_data[value].min(),
                        round(baseline_data[value].std(), 2), round(baseline_data[value].var(), 2)])
            table.add_row(["Data source", round(datasource_data[value].mean(), 2),
                        datasource_data[value].max(), datasource_data[value].min(),
                        round(datasource_data[value].std(), 2), round(datasource_data[value].var(), 2)])
            output += table.get_string() + "\n\n"
    
    return output


def calculate_percentage_change(dataframe_ref, dataframe):  
    """Calculate the percentage change of the mean of the values for each metric, 
    as well as the maximum percentage change of the individual values, in order to detect peaks.

    Args:
        dataframe_ref: data frame with the references values.
        dataframe: data frame with the values to compare.
    """  
    daemons = dataframe_ref['Daemon'].unique()

    for daemon in daemons:
        print(f"\nDaemon: {daemon}")
        ref_daemon_data = dataframe_ref[dataframe_ref['Daemon'] == daemon]
        new_daemon_data = dataframe[dataframe['Daemon'] == daemon]
        
        for value in STATS_MAPPING.values():
            ref_mean = ref_daemon_data[value].mean()
            new_mean = new_daemon_data[value].mean()
            ref_values = ref_daemon_data[value].dropna().values
            new_values = new_daemon_data[value].dropna().values
            
            if ref_mean != 0:
                mean_percentage_change = ((new_mean - ref_mean) / ref_mean) * 100
            else:
                mean_percentage_change = 0

            max_percentage_change = 0
            for ref, new in zip(ref_values, new_values):
                if ref != 0:
                    individual_change = abs((new - ref) / ref) * 100
                else:
                    individual_change = 0
                if individual_change > max_percentage_change:
                    max_percentage_change = individual_change
            
            print(f"\n  Metric '{value}':")
            print(f"    Reference Mean: {ref_mean}")
            print(f"    New Mean: {new_mean}")
            print(f"    Mean Percentage Change: {mean_percentage_change}%")
            print(f"    Max Percentage Change: {max_percentage_change}%")
        print("\n")


def main():
    parameters = get_parameters()
    validate_parameters(parameters, parameters.data_source)
    baseline = load_dataframe(parameters.baseline_data)
    datasource = load_dataframe(parameters.data_source)
    print_dataframes_stats(baseline, datasource)
    #calculate_basic_statistics(baseline)
    #data_comparison_test(parameters.baseline_data, parameters.data_source)
    #calculate_percentage_change(baseline, datasource)


if __name__ == '__main__':
    main()
