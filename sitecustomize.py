"""
Site-wide runtime customizer for SNMK.
Automatically executed on Python startup when PYTHONPATH contains the repository root.
Ensures uniform datetime.UTC availability on Python 3.10 and earlier.
"""

import datetime
import sys

if not hasattr(datetime, "UTC"):
    setattr(datetime, "UTC", datetime.timezone.utc)
    if "datetime" in sys.modules:
        sys.modules["datetime"].UTC = datetime.timezone.utc
