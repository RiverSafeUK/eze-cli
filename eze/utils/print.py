"""Print helpers
"""


def pretty_print_table(table: list, has_nothing_message: bool = True) -> None:
    """given kv with print it as a pretty printed table

    output is compatible with markdown"""
    # WARNING: special print functions
    if len(table) == 0:
        if has_nothing_message:
            print("Nothing to display")
        return

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

    print("", end="|")
    for column_name in column_sizes:
        column_size = column_sizes[column_name]
        print(" " + column_name.ljust(column_size), end=" |")
    print()

    print("", end="|")
    for column_name in column_sizes:
        column_size = column_sizes[column_name]
        print(" " + "-" * column_size + " ", end="|")
    print()

    for table_row in table:
        print("", end="|")
        for column_name in column_sizes:
            column_size = column_sizes[column_name]
            column_value = table_row[column_name]
            print(" " + column_value.ljust(column_size), end=" |")
        print()
