#!/bin/sh
set -e

./supervisor-backend-internal & 
./supervisor-backend

tail -f /dev/null