"""Allow ``python -m lintest`` execution."""

import sys

from lintest.main import main

if __name__ == "__main__":
    sys.exit(main())
