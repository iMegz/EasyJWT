FROM ticarpi/jwt_tool

# Build tooling in case pip has to compile cryptography/cffi from source
# rather than use a prebuilt wheel (musllinux wheels aren't always available
# for every architecture/Python combo, and cryptography's Rust extension
# needs a Rust toolchain to build from source). gmp-dev/mpfr-dev/mpc-dev are
# for gmpy2, which also has no musllinux wheel and always builds from
# source here; it's what makes the "recover public key from two tokens"
# feature fast enough to use (CPython's own bignum math on numbers that
# size is impractically slow).
RUN apk add --no-cache libffi-dev gcc musl-dev openssl-dev rust cargo gmp-dev mpfr-dev mpc1-dev

RUN pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir flask "pyjwt[crypto]" gmpy2

# Pre-create jwt_tool's config file at build time so the first request a
# container handles never hits its interactive first-run setup message.
RUN python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U >/dev/null 2>&1 || true

COPY webui /webui
COPY wordlists /wordlists

EXPOSE 5000

ENV PORT=5000

ENTRYPOINT ["python3", "/webui/app.py"]
