#!/bin/sh
# The runner injects the per-run flag through $FLAG. The sanity check
# exercises the contract's surfaces: a file and an HTTP service. The flag
# is split in three, one part each:
#   part1:  /code/flag.txt, the files surface (shipped to the harness)
#   part2:  the HTTP target, at /flag.txt
#   part3:  the HTTP target, at /brace.txt
# python:3.12-alpine base: the production runtime runs it reliably.
part1='flag{'
part2=$(printf '%s' "${FLAG:-}" | sed -e 's/^flag{//' -e 's/}$//')
part3='}'
echo "$part1" > /code/flag.txt
echo "The flag is split in three: the opening flag{ in this directory, the hex middle on the HTTP target at /flag.txt, the closing brace on the same target at /brace.txt. The format tells the order." > /code/README.txt
mkdir -p /srv
echo "$part2" > /srv/flag.txt
echo "$part3" > /srv/brace.txt
cd /srv
exec python3 -m http.server 80
