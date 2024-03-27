# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from argparse import ArgumentParser
from pydantic import BaseModel


def pydantic_argument_parser(parser: ArgumentParser, model: BaseModel):
    "Add Pydantic model to an ArgumentParser"
    fields = model.model_fields
    for name, field in fields.items():
        parser.add_argument(
            f"--{name}", 
            dest=name, 
            type=field.type_, 
            default=field.default,
            help=field.field_info.description,
        )
    return parser.parse_args()
