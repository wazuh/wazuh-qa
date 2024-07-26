import pytest
from wazuh_testing.scripts.statistical_data_analyzer import comparison_basic_statistics, STATS_MAPPING, t_student_test, t_levene_test, t_anova_test, STATISTICS_LIST

def test_comparison(load_data, config):
    """
    
    """
    baseline, datasource, threshold, confidence_level = load_data
    errors = []
    daemons = config['Daemons']
    metrics = config['Metrics']
    stats = config['Stats']
    threshold_value = threshold / 100
    p_value = (100 - confidence_level) / 100

    for daemon in daemons:
        for value in metrics:
            t_p_value =  t_student_test(baseline, datasource, value)
            l_p_value =  t_levene_test(baseline, datasource, value)
            a_p_value =  t_anova_test(baseline, datasource, value)

            if t_p_value < p_value or l_p_value < p_value or a_p_value < p_value:
                for stat in stats:
                    try:
                        assert comparison_basic_statistics(baseline, datasource, daemon, value, stat, threshold_value) != 1
                    except AssertionError:
                        errors.append(f"Difference over {threshold_value*100}% detected in '{daemon}' - '{value}' - '{stat}'")

    if errors:
        pytest.fail("\n".join(errors))
