"""
SNMK Core Package.
"""

import datetime
import sys

# Python 3.10 backwards compatibility shim
if not hasattr(datetime, "UTC"):
    setattr(datetime, "UTC", datetime.timezone.utc)
    if "datetime" in sys.modules:
        sys.modules["datetime"].UTC = datetime.timezone.utc
