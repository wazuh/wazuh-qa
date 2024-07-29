import pytest
from wazuh_testing.scripts.statistical_data_analyzer import comparison_basic_statistics, t_student_test, t_levene_test, t_anova_test

def test_comparison(load_data, config):
    """The main test of the module. It checks if any statistical test detects significant changes and if so, 
    compares the statistics of both data sets to detect changes with respect to a threshold value.  

    Args:
        load_data: fixture that contains baseline and data source Dataframes, and the
        threshold and confidence level values.
        config: Dict that contains the items to be analyzed.
    """
    baseline, datasource, confidence_level = load_data
    errors = []
    daemons = config['Daemons']
    metrics = config['Metrics']
    #stats = config['Stats']
    p_value = (100 - confidence_level) / 100

    for daemon in daemons:
        for value, thresholds in metrics.items():
            #threshold_value = float(threshold_str) / 100
            t_p_value =  t_student_test(baseline, datasource, value)
            l_p_value =  t_levene_test(baseline, datasource, value)
            a_p_value =  t_anova_test(baseline, datasource, value)

            if t_p_value < p_value or l_p_value < p_value or a_p_value < p_value:
                for stat, threshold_value in thresholds.items():
                    threshold_value = threshold_value / 100
                    try:
                        assert comparison_basic_statistics(baseline, datasource, daemon, value, stat, threshold_value) != 1
                    except AssertionError:
                        errors.append(f"Difference over {threshold_value*100}% detected in '{daemon}' - '{value}' - '{stat}'")

    if errors:
        pytest.fail("\n".join(errors))
