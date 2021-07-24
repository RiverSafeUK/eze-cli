"""
Main entry point for eze cli, passes off to cli module
python -m eze

.. note:: https://click.palletsprojects.com/en/7.x/api/
"""

# pylint: disable=unexpected-keyword-arg

from eze.cli.main import cli

if __name__ == "__main__":
    cli(prog_name="eze")
