import argparse
import os
import sys
import pandas as pd
from prettytable import PrettyTable
from scipy.stats import mannwhitneyu, ttest_ind, levene, f_oneway

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

def get_parameters():
    """Get and process script parameters.
    
    return:
        argparse.Namespace: Script parameters.
    """
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-b', '--baseline', metavar='<file>', type=str, action='store',
                            help='Baseline file to compare', required=True, dest='baseline_data')

    arg_parser.add_argument('-f', '--file', metavar='<file>', type=str, action='store',
                            help='Data file to compare', required=True, dest='data_source')
    
    return arg_parser.parse_args()

def validate_parameters(parameters, dataframe):
    """Validate the input parameters

    Args:
        parameters (argparse.Namespace): Script parameters.
        datframe: data frame obtained from the data source file
    """
    # Check that the file exists
    if not os.path.exists(parameters.baseline_data) or not os.path.exists(parameters.data_source):
        print(f"The files provided do not exist")
        sys.exit(1)
    
    # Check that the source file has more than 0 rows
    data_length = len(dataframe)    
    if data_length == 0:
        print(f"The source '{dataframe}' has not data rows or it has not CSV format")
        sys.exit(1)

def basic_statistics(dataframe):
    """Calculate basic statistics on the data source file for comparison.
    
    Args:
        data_source: Data file to compare.
    """    
    print(f"\nStatistics values of each daemon:\n")
    daemons = dataframe['Daemon'].unique()
    for daemon in daemons:
        table = PrettyTable()
        table.title = daemon
        table.field_names = ['Metric', 'Mean', 'Median', 'Max value', 'Min value', 'Standard deviation', 'Variance']

        daemon_data = dataframe[dataframe['Daemon'] == daemon]
        for value in STATS_MAPPING.values():
            table.add_row([value, round(daemon_data[value].mean(), 2), round(daemon_data[value].median(), 2),
                           round(daemon_data[value].max(), 2), round(daemon_data[value].min(), 2),
                           round(daemon_data[value].std(), 2), round(daemon_data[value].var(), 2)])
        
        print("\n")
        print(table)

def data_comparison_test(dataframe_ref, dataframe, percentage=95):
    """Calculate statistics values for Mann-Whitney U, t-Student and Levene tests. Also,
    it detect if there are significant difference detected between both values.

    Args:
        dataframe_ref: data frame with the references values.
        dataframe: data frame with the values to compare.
        percentage: percentage of confidence level.
    """
    alpha = float((100 - percentage) / 100)
    daemons = dataframe_ref['Daemon'].unique()
    for daemon in daemons:
        print(f"\nDaemon: {daemon}\n")
        ref_daemon_data = dataframe_ref[dataframe_ref['Daemon'] == daemon]
        new_daemon_data = dataframe[dataframe['Daemon'] == daemon]

        for value in STATS_MAPPING.values():
            ref_values = ref_daemon_data[value].dropna()
            new_values = new_daemon_data[value].dropna()

            # Mann-Whitney U
            u_stat, u_p_value = mannwhitneyu(ref_values, new_values, alternative='two-sided')
            # t-Student
            t_stat, t_p_value = ttest_ind(ref_values, new_values, equal_var=False)
            # Levene
            l_stat, l_p_value = levene(ref_values, new_values)

            print(f"\nMetric '{value}':")
            print(f"    - Mann-Whitney U Test: U-Statistic={u_stat}, p-value={u_p_value}")
            print(f"    - t-Student Test: t-Statistic={t_stat}, p-value={t_p_value}")
            print(f"    - Levene's Test: Statistic={l_stat}, p-value={l_p_value}")

            if u_p_value < alpha:
                print(f"\n  Significant difference detected in '{value}' with {percentage}% confidence (Mann-Whitney U Test).")
            if t_p_value < alpha:
                print(f"\n  Significant difference detected in '{value}' with {percentage}% confidence (t-Test).")
            if l_p_value < alpha:
                print(f"\n  Variance difference detected in '{value}' with {percentage}% confidence (Levene's Test).")
        print("\n")

def anova_analysis(dataframe_ref, dataframe, percentage=95):
    """ Analyze the data from both dataframes using ANOVA analysis.
    
    Args:
        dataframe_ref: data frame with the references values.
        dataframe: data frame with the values to compare.
        percentage: percentage of confidence level.
    """
    alpha = float((100 - percentage) / 100)
    daemons = dataframe_ref['Daemon'].unique()
    for daemon in daemons:
        print(f"\n\nDaemon: {daemon}")
        ref_daemon_data = dataframe_ref[dataframe_ref['Daemon'] == daemon]
        new_daemon_data = dataframe[dataframe['Daemon'] == daemon]

        for value in STATS_MAPPING.values():
            ref_values = ref_daemon_data[value].dropna()
            new_values = new_daemon_data[value].dropna()
            f_stat, p_value = f_oneway(ref_values, new_values)

            print(f"\nANOVA result for {value}:")
            print(f"  F-statistic: {f_stat}")
            print(f"  p-value: {p_value}")
            if p_value < alpha:
                print(f"\n  Significant difference detected (p-value < {alpha}). The means are significantly different.")

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
    baseline_dataframe = pd.read_csv(parameters.baseline_data)
    dataframe = pd.read_csv(parameters.data_source)
    validate_parameters(parameters, dataframe)
    #basic_statistics(dataframe)
    data_comparison_test(baseline_dataframe, dataframe)
    #anova_analysis(baseline_dataframe, dataframe)
    #calculate_percentage_change(baseline_dataframe, dataframe)

if __name__ == '__main__':
    main()