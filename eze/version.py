"""
Simple entry point for passing version to simple cli scripts
python -m eze.version
"""

from eze import __version__

if __name__ == "__main__":
    print(__version__)
