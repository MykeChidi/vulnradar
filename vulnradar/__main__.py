"""
Entry point for running VulnRadar as a module: python -m vulnradar
"""

import sys
from .cli import main

if __name__ == '__main__':
    sys.exit(main())