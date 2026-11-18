"""
Pytest root configuration and environment shims for SNMK.
Provides backward-compatibility shims for Python 3.10 and earlier runtimes.
"""

import datetime
import sys

# Python 3.10 backwards compatibility shim: datetime.UTC was added in Python 3.11
if not hasattr(datetime, "UTC"):
    setattr(datetime, "UTC", datetime.timezone.utc)
    if "datetime" in sys.modules:
        sys.modules["datetime"].UTC = datetime.timezone.utc
