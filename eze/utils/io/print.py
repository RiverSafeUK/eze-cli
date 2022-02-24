"""Print helpers
"""
import json


def generate_markdown_table(table: list, has_nothing_message: bool = True) -> str:
    """given kv create markdown string of table"""
    # WARNING: special print functions
    if len(table) == 0:
        if has_nothing_message:
            return "Nothing to display"
        return ""

    markdown_str: str = ""

    sample_entry = table[0]
    column_sizes = {}
    for column in sample_entry:
        column_sizes[column] = 0
        column_name_size = len(column)
        if column_name_size > column_sizes[column]:
            column_sizes[column] = column_name_size

    for table_row in table:
        for column in table_row:
            column_size = len(table_row[column])
            if column_size > column_sizes[column]:
                column_sizes[column] = column_size

    markdown_str += "|"
    for column_name in column_sizes:
        column_size = column_sizes[column_name]
        markdown_str += " " + column_name.ljust(column_size) + " |"

    markdown_str += "\n|"
    for column_name in column_sizes:
        column_size = column_sizes[column_name]
        markdown_str += " " + ("-" * column_size) + " " + "|"

    for table_row in table:
        markdown_str += "\n|"
        for column_name in column_sizes:
            column_size = column_sizes[column_name]
            column_value = table_row[column_name]
            markdown_str += " " + column_value.ljust(column_size) + " |"
        markdown_str += ""
    return markdown_str


def pretty_print_table(table: list, has_nothing_message: bool = True) -> None:
    """given kv with print it as a pretty printed table

    output is compatible with markdown"""
    markdown_table = generate_markdown_table(table, has_nothing_message)
    print(markdown_table)


def pretty_print_json(obj) -> str:
    """Helper, takes generic python class/object and convert into pretty json str"""
    return json.dumps(obj, default=vars, indent=2, sort_keys=True)
