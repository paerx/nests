#!/bin/sh
set -e

# start backend
/app/nests-api &

# start frontend
/app/nests-front &

wait -n
