"""Start HostGuard from this file's own path:  pythonw <...>/hostguard/launch.py monitor run

HostGuard's background processes (the monitor, the dashboard) and its shortcuts are started this
way rather than with `python -m hostguard`, so that their command lines carry this folder's full
path. That is how a scan recognises HostGuard's own processes and its own startup entry, and it
works the same from a source checkout and from a copy installed with pip.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# Python puts this file's folder first on the import path, which would let the package's modules
# be imported under bare names. Point that entry at the folder that contains the package instead.
if sys.path and os.path.abspath(sys.path[0] or os.getcwd()) == _HERE:
    sys.path[0] = os.path.dirname(_HERE)
else:
    sys.path.insert(0, os.path.dirname(_HERE))

from hostguard.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
