#!/bin/bash
#
# runserver.sh
#
# development script for server starting
#

export PYTHONPATH=$PYTHONPATH:`pwd`

examples/avlibserver.py

exit 0
