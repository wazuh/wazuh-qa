# Copyright (C) 2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Module that defines the graphical interface of the application."""

from typing import Any, Dict

import dash_mantine_components as dmc
from dash import dcc
from style import container_style, styles

from data_loader import load_initial_data_from_db


def create_layout(config: Dict[str, Any]) -> dmc.Container:
    """Main function where the interface elements are described.

    Args:
        config (Dict[str, Any]): Dict containing the YAML file information.

    Returns:
        layout (dmc.Container): Dash container with application information.
    """
    process_values_list, column_names, organized_files = load_initial_data_from_db(config)
    component_name = config.get('Component', [])[0].upper()

    layout = dmc.Container([
        dmc.Title(f"DATA VISUALIZATION - {component_name}", align="center", c="blue", size="h1",
                style={'text-decoration': 'underline', 'margin-bottom':'10px'}),
        dmc.Card(
            dmc.Grid([
                dmc.Col(
                    [
                        dmc.Title("Select Process:", align="center", size="h3"),
                        dcc.Checklist(
                            id='process',
                            options=[{'label': val, 'value': val} for val in process_values_list],
                            style=styles['checklist'],
                            inputStyle=styles['input']
                        ),
                    ],
                    span=6,
                    style=styles['col']
                ),
                dmc.Col(
                    [
                        dmc.Title("Select Metric:", align="center", size="h3"),
                        dcc.RadioItems(
                            id='metric',
                            options=[{'label': col, 'value': col} for col in column_names], 
                            value=column_names[0],
                            style=styles['checklist'],
                            inputStyle=styles['input']
                        ),
                    ],
                    span=6,
                    style=styles['col']
                ),
            ], align="start", justify="center"),
            style=styles['main']
        ),
        dmc.Title("Select Version:", align="center", size="h3"),
        dmc.Card(
            dmc.Grid(
                children=[
                    dmc.Col(
                        [
                            dmc.Title(commit, align="center", size="h4"),
                            dcc.Checklist(
                                id={'type': 'file-checklist', 'index': commit},
                                options=[{'label': file, 'value': file} for file in files],
                                style=styles['versions'],
                                inputStyle=styles['input']
                            )
                        ],
                        span=4,
                        style=styles['col']
                    ) for commit, files in organized_files.items()
                ],
                style={
                    'display': 'flex', 
                    'flex-direction': 'row', 
                    'justify-content': 'center'
                }
            ),
            style=styles['main']
        ),
        dmc.Card(
            dcc.Graph(id='metric-graph'),
            style=styles['graph']
        ),    
        dcc.Store(id='filtered-data'),
    ], 
    style=container_style)

    return layout
