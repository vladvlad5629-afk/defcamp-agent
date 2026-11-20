#!/bin/sh
# Build the harness image and save it as <name>.tar, the file you upload.
#
#   sh build.sh              -> my-harness.tar
#   sh build.sh team-x       -> team-x.tar
set -eu

name="${1:-my-harness}"
cd "$(dirname "$0")"

# Buildx produces an OCI layout on current Docker. Convert it to the legacy
# Docker archive expected by the competition loader (with `repositories`).
oci_archive="$name.oci.tar"
docker buildx build --platform linux/amd64 --tag "$name:latest" \
  --output "type=docker,dest=$oci_archive" harness

if command -v skopeo >/dev/null 2>&1; then
  skopeo copy "oci-archive:$oci_archive" "docker-archive:$name.tar:$name:latest"
else
  docker run --rm -v "$(pwd):/work" quay.io/skopeo/stable \
    copy "oci-archive:/work/$oci_archive" "docker-archive:/work/$name.tar:$name:latest"
fi
rm -f "$oci_archive"
tar -tf "$name.tar" | grep -qx 'repositories'
docker load --input "$name.tar" >/dev/null

size=$(wc -c < "$name.tar" | tr -d ' ')
echo "wrote $name.tar ($((size / 1048576)) MB). Upload it on the Harnesses page."
if [ "$size" -gt 1073741824 ]; then
  echo "warning: over the 1 GiB upload limit; try 'gzip $name.tar' or a smaller base image" >&2
fi
