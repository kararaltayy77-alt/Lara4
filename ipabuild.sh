#!/bin/bash
set -eo pipefail
cd "$(dirname "$0")"

# The project is inside Lara3-fixed/
cd Lara3-fixed

exec ./ipabuild.sh "$@"
