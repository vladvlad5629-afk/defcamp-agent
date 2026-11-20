# v2 dispatcher harness: Node agent + pwn/rev/crypto toolchain (Debian for
# reliable pwntools). No internet at run time, so everything is baked in.
FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-dev python3-venv \
      gdb binutils file curl netcat-openbsd openssl xxd jq ruby git \
      gcc libc6-dev libffi-dev libssl-dev \
      libgmp-dev libmpfr-dev libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# CTF python toolkit (build-time only; no network at run time).
RUN pip3 install --no-cache-dir --break-system-packages \
      pwntools pycryptodome gmpy2 sympy requests ROPgadget \
    && python3 -c "import pwn, Crypto, gmpy2, sympy; print('py toolkit ok')"

# v5 REV auto-solver: angr on an ISOLATED Python 3.12 (angr 10.x needs >=3.12;
# that is the real fix for the bitstring/pycparser dep-hell on 3.11). Use uv to
# fetch a standalone CPython 3.12 at build time and install prebuilt wheels.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
RUN uv python install 3.12 \
    && uv venv --python 3.12 /opt/angr \
    && VIRTUAL_ENV=/opt/angr uv pip install "angr==10.0.7" "cle==10.0.7" "pyvex==10.0.7" "archinfo==10.0.7" \
    && /opt/angr/bin/python -c "import angr; cp=angr.claripy; cp.BVS('x',8); print('angr', angr.__version__, 'ok on', __import__('sys').version.split()[0])"

# crypto helper tools (system 3.11): hashpumpy (length-extension), randcrack (MT19937).
RUN pip3 install --no-cache-dir --break-system-packages hashpumpy randcrack || true

# Agent settings (platform does not set these).
ENV HARNESS_FORMAT=chat \
    AGENT_MAX_STEPS=40 \
    NODE_NO_WARNINGS=1 \
    PWNLIB_NOTERM=1 \
    PYTHONUNBUFFERED=1

COPY pwn_recon.py /app/pwn_recon.py
COPY crypto_recon.py /app/crypto_recon.py
COPY web_recon.py /app/web_recon.py
COPY solvers/ /app/solvers/
COPY auto_solve.py /app/auto_solve.py
COPY angr_solve.py /app/angr_solve.py
# The source package ships agent.mjs.  Keeping the image entry point aligned
# with that name makes a source rebuild reproducible.
COPY agent.mjs /app/agent.mjs
ENTRYPOINT ["node", "/app/agent.mjs"]

