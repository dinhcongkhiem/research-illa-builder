#!/bin/sh
set -e

./illa-builder-backend &
./illa-builder-backend-websocket &
./illa-builder-backend-internal &

tail -f /dev/null