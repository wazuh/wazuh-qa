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