import os
import yaml
import pandas as pd
from prettytable import PrettyTable
from scipy.stats import ttest_ind, levene, f_oneway

class DataLoader:
    """
    """
    def __init__(self, baseline_path, datasource_path, items_path):
        """
        """
        self.baseline_path = baseline_path
        self.datasource_path = datasource_path
        self.items_path = items_path
        self.validate_paths()
        self.baseline = self.load_dataframe(baseline_path)
        self.datasource = self.load_dataframe(datasource_path)
        self.metrics = self.load_metrics()
        self.process_name, self.processes = self.load_yaml_items(self.items_path)
        

    def validate_paths(self):
        """
        """
        if not os.path.exists(self.baseline_path) or not os.path.exists(self.datasource_path):
            raise ValueError(f"One or both of the provided CSV files do not exist")
        
        if not os.path.exists(self.items_path):
            raise ValueError(f"The YML file does not exit") 
          

    def load_dataframe(self, path):
        """
        """
        dataframe = pd.read_csv(path)
        if len(dataframe) == 0:
            raise ValueError(f"The file {path} has not data rows or it has not CSV format")

        return dataframe
        
        
    def load_metrics(self):
        """
        """
        metrics = [col for col in self.baseline.columns if pd.api.types.is_numeric_dtype(self.baseline[col])]
        return metrics
    
    
    def load_yaml_items(self, yaml_path):
        """
        """
        if not os.path.exists(yaml_path):
            raise ValueError(f"Items yaml file '{yaml_path}' does not exist")

        with open(yaml_path, 'r') as file:
            config = yaml.safe_load(file)
        
        processes_section = config.get('Processes', {})
        process_name = list(processes_section.keys())[0]
        processes = processes_section[process_name]

        return process_name, processes
    
    
    def print_dataframes_stats(self):
        """Generate a PrettyTable with the statistics for each process and metric.

        Args:
            baseline: Dataframe with the baseline values.
            datasource: Dataframe with the values to compare.
        """
        output = ""

        for process in self.processes:
            baseline_data = self.baseline[self.baseline[self.process_name] == process]
            datasource_data = self.datasource[self.datasource[self.process_name] == process]

            for metric in self.metrics:
                table = PrettyTable()
                table.title = process + " - " + metric
                table.field_names = ['Name', 'Mean', 'Max value', 'Min value', 'Standard deviation', 'Variance']
                table.add_row(["Baseline", round(baseline_data[metric].mean(), 2),
                            baseline_data[metric].max(), baseline_data[metric].min(),
                            round(baseline_data[metric].std(), 2), round(baseline_data[metric].var(), 2)])
                table.add_row(["Data source", round(datasource_data[metric].mean(), 2),
                            datasource_data[metric].max(), datasource_data[metric].min(),
                            round(datasource_data[metric].std(), 2), round(datasource_data[metric].var(), 2)])
                output += table.get_string() + "\n\n"
        
        return output


class StatisticalComparator:
    """
    """   
    def calculate_basic_statistics(self, dataframe, metric, stat):
        """
        """
        value = 0
        if stat == 'Mean':
            value = round(float(dataframe[metric].mean()), 2)
        elif stat == 'Median':
            value = round(float(dataframe[metric].median()), 2)
        elif stat == 'Max value':
            value = round(float(dataframe[metric].max()), 2)
        elif stat == 'Min value':
            value = round(float(dataframe[metric].min()), 2)
        elif stat == 'Standard deviation':
            value = round(float(dataframe[metric].std()), 2)
        elif stat == 'Variance':
            value = round(float(dataframe[metric].var()), 2)

        return value


    def comparison_basic_statistics(self, baseline, datasource, metric, stat, threshold):
        """Compares the percentage change in a given statistic between the two data sets, and 
        returns whether there is a significant change based on a threshold value.

        Args:
            baseline: Dataframe with the baseline data.
            datasource: Dataframe with the data source.
            value: metric from which the statistics to be compared are obtained.
            stat: concrete statistic to be compared.
            threshold: Threshold for comparison. If not specified, default is 5%.

        Returns:
            discrepancie: If the percentage difference is greater than the threshold,
            it returns 1, otherwise it returns 0.
        """
        discrepancy = 0
        baseline_value = self.calculate_basic_statistics(baseline, metric, stat)
        dataframe_value = self.calculate_basic_statistics(datasource, metric, stat)

        if baseline_value != 0:
            diff = abs(baseline_value - dataframe_value) / baseline_value
        else:
            diff = abs(baseline_value - dataframe_value)
        
        if diff >= threshold:
            discrepancy = 1
        
        return discrepancy


class StatisticalTests:
    """
    """
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

        _, t_p_value = ttest_ind(ref_values, new_values, equal_var=False)

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

        _, l_p_value = levene(ref_values, new_values)

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

        _, a_p_value = f_oneway(ref_values, new_values)

        return a_p_value
