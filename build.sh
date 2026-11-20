#!/bin/sh
# Build the harness image and save it as <name>.tar, the file you upload.
#
#   sh build.sh              -> my-harness.tar
#   sh build.sh team-x       -> team-x.tar
set -eu

name="${1:-my-harness}"
cd "$(dirname "$0")"

# Export a Docker image archive explicitly. Recent Docker/containerd stores
# make `docker save` emit OCI layouts, which older event loaders reject.
docker buildx build --platform linux/amd64 --tag "$name:latest" \
  --output "type=docker,dest=$name.tar" harness

if tar -tf "$name.tar" | grep -qx 'oci-layout'; then
  echo "error: OCI archive produced; expected Docker image archive" >&2
  exit 1
fi

size=$(wc -c < "$name.tar" | tr -d ' ')
echo "wrote $name.tar ($((size / 1048576)) MB). Upload it on the Harnesses page."
if [ "$size" -gt 1073741824 ]; then
  echo "warning: over the 1 GiB upload limit; try 'gzip $name.tar' or a smaller base image" >&2
fi
