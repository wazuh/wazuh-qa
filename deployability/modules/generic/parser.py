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

# 1. Create and parse command line arguments
# parser = ArgumentParser()

# 2. Turn the fields of the model as arguments of the parser
# add_model(parser, MyItem)

# 3. Parse the command-line arguments
# args = parser.parse_args()