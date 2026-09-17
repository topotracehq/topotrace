# Test image for agent/ubuntu/muster-agent.sh -- NOT part of Muster's own
# runtime images (the main Dockerfile at the repo root). This exists so
# you can exercise the real agent script against a real (if
# containerized) Ubuntu host and a running Muster server, without
# needing a spare Linux machine.
#
# Build from the repo root so the COPY below can reach the script:
#   docker build -f agent/ubuntu/Dockerfile -t muster-ubuntu-agent .
# (docker compose, see docker-compose.yml's "ubuntu-agent" service, does
# this for you.)
FROM ubuntu:24.04

# bash, tar, gzip, and coreutils (wc, cat, uname, ...) all ship in the
# stock Ubuntu image already -- nothing to install for the script itself.
# ca-certificates isn't needed either: MUSTER1 is a raw TCP protocol, no
# TLS involved.

COPY agent/ubuntu/muster-agent.sh /usr/local/bin/muster-agent.sh
RUN chmod +x /usr/local/bin/muster-agent.sh

ENTRYPOINT ["/usr/local/bin/muster-agent.sh"]
# No default CMD -- --muster-host is required, so a bare `docker run`
# fails fast with the script's own usage message rather than silently
# doing nothing. Compose supplies real arguments (see docker-compose.yml).
