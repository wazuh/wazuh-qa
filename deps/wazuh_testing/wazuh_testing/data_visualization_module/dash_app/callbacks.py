# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Module containing the callbacks of the Dash application to update the information displayed."""

import plotly.express as px
from typing import Any, Dict, List

from cache import cache
from dash import ALL, Dash, Input, Output

from data_loader import load_csv_files_from_db, extract_config_parameters


def callbacks(app: Dash, config: Dict[str, Any]) -> None:
    """Main function that defines all callbacks.

    Args:
        app (Dash): Dash application.
        config (Dict[str, Any]): Dict containing the YAML file information.
    """
    component, _, _, process_name = extract_config_parameters(config)

    @app.callback(
        Output('filtered-data', 'data'),
        Input('process', 'value'),
        Input({'type': 'file-checklist', 'index': ALL}, 'value')
    )
    @cache.memoize()
    def update_process(processes: List[str], versions: List[List[str]]) -> List[Dict[str, Any]]:
        """Callback to update the filtered data based on selected processes and versions.

        Args:
            processes (List[str]): List of selected processes.
            versions (List[List[str]]): List of selected versions for each component.

        Returns:
            (List[Dict[str, Any]]): the filtered data as a list of dictionaries.
        """
        if not processes or not versions:
            return []

        all_selected_versions = []
        for version_list in versions:
            if version_list:
                all_selected_versions.extend(version_list)

        filtered_df = load_csv_files_from_db(processes, all_selected_versions, component, process_name)

        return filtered_df.to_dict('records')

    @app.callback(
        Output('metric-graph', 'figure'),
        Input('metric', 'value'),
        Input('filtered-data', 'data')
    )
    def update_graph(metric: str, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Callback to update the graph based on selected metric and filtered data.

        Args:
            metric (str): the selected metric to plot.
            data (List[Dict[str, Any]]): the filtered data to plot.

        Returns:
            fig (Dict[str, Any]): the figure object to be rendered.
        """
        if not data or not metric:
            return {}

        fig = px.line(data, x="seconds_since_start", y=metric, color='process_version',
                      title=f"{metric} for selected procceses and versions", width=1800, height=800)
        return fig
