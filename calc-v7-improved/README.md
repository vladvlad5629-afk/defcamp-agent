# calc-v7 improved

This source tree is derived from the supplied calc-v7 archive. The original
archive remains untouched at `work/calc-v7-backup` and its SHA-256 is recorded
in the chat history.

Changes in this revision:

- Docker builds now copy the packaged `agent.mjs` file.
- File and binary paths passed into recon commands are shell quoted.
- Target parsing accepts only `host:port` values with a numeric port and splits
  at the final colon, preserving IPv6-style host values.
- The time reserve is 60 seconds so the agent retains more time for solving,
  while leaving a final submission window.

Build from this directory with:

```sh
docker build --platform linux/amd64 -t calc-v7-improved .
docker save -o calc-v7-improved.tar calc-v7-improved
```

The image cannot be built in this workspace because Docker is unavailable here.
Run the commands on a Docker-enabled machine or through the team's existing
GitHub Actions build workflow, then validate the image against the platform's
practice challenge before uploading it as a separate harness.

