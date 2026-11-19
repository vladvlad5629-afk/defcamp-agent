#!/bin/sh
# Build the harness image and save it as <name>.tar, the file you upload.
#
#   sh build.sh              -> my-harness.tar
#   sh build.sh team-x       -> team-x.tar
set -eu

name="${1:-my-harness}"
cd "$(dirname "$0")"

# The event runs linux/amd64. On Apple Silicon this builds under emulation,
# which is slower but gives the image the platform can run.
docker build --platform linux/amd64 -t "$name" harness
docker save -o "$name.tar" "$name"

size=$(wc -c < "$name.tar" | tr -d ' ')
echo "wrote $name.tar ($((size / 1048576)) MB). Upload it on the Harnesses page."
if [ "$size" -gt 1073741824 ]; then
  echo "warning: over the 1 GiB upload limit; try 'gzip $name.tar' or a smaller base image" >&2
fi
